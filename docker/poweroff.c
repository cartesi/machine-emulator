#define HTIF_BASE_ADDR 0x40008000
#define HTIF_SIZE 16

#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void) {
    int memfd = open("/dev/mem", O_RDWR);
    unsigned char* shmem = mmap(0, HTIF_SIZE,
        PROT_WRITE | PROT_READ, MAP_SHARED, memfd, HTIF_BASE_ADDR);
    *((uint32_t*) (shmem)) = 1;
    *((uint32_t*) (shmem+4)) = 0;
    return 0;
}
