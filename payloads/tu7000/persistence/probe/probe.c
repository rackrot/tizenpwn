#include <fcntl.h>
#include <unistd.h>

#ifndef TIZENPWN_PROBE_FILE
#define TIZENPWN_PROBE_FILE "/tmp/tizenpwn-memfd-ok"
#endif

int main(void) {
    const char message[] = "TIZENPWN_MEMFD_OK\n";
    int file = open(
        TIZENPWN_PROBE_FILE,
        O_WRONLY | O_CREAT | O_TRUNC,
        0644
    );
    if (file >= 0) {
        write(file, message, sizeof(message) - 1);
        close(file);
    }
    write(1, message, sizeof(message) - 1);
    return 0;
}
