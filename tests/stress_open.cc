#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <cstdio>

int main(int argc, const char** argv) {
    if (argc < 3) {
        printf("Usage: %s <filename> <num iterations>\n", argv[0]);
        exit(1);
    }
    for (int i=0; i < atoi(argv[2]); ++i)  {
        int fd = open(argv[1], 0);
        if (fd < 0) {
            printf("Failed to open file on iteration: %d, %d\n", i, fd);
            exit(1);
        }
        close(fd);
    }
    printf("%d iterations done!\n", atoi(argv[2]));
    return 0;
}