#define HTIF_BASE_ADDR 0x40008000
#define HTIF_SIZE 16

#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    int memfd = open("/dev/mem", O_RDWR);
    volatile unsigned char* shmem = mmap(0, HTIF_SIZE,
        PROT_WRITE | PROT_READ, MAP_SHARED, memfd, HTIF_BASE_ADDR);
    uint32_t exit_code = 0;
    if (argc > 1) {
        int end;
        if (sscanf(argv[1], "%" SCNu32 "%n", &exit_code, &end) != 1 ||
            argv[1][end] != '\0') {
            fprintf(stderr, "htifexit [<exit code>]\n");
            exit(0);
        }
    }
    *((uint32_t*) (shmem)) = (exit_code << 1) + 1;
    *((uint32_t*) (shmem+4)) = 0;
    return 0;
}
