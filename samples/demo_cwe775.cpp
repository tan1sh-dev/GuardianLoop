// Intentionally vulnerable sample: CWE-775 non-memory resource leak.
//
// Three patterns:
//   1. fopen() result not fclose()d on an error path.
//   2. socket() fd not close()d before return.
//   3. open() fd not close()d before return.
//
// Repeated calls will exhaust file descriptor limits, causing DoS.
// A correct patch must close every resource on all exit paths, or use RAII.

#include <cstdio>
#include <cstdlib>
#include <cstring>

// Simulate POSIX headers for pattern matching
// (actual compilation would need <fcntl.h>, <sys/socket.h>, <unistd.h>)
int socket(int domain, int type, int protocol);
int open(const char* path, int flags, int mode);
int close(int fd);

void leaky_file_read(const char* path) {
    // VULNERABLE: fp is never closed — fclose(fp) is missing.
    FILE* fp = fopen(path, "r");
    if (fp == NULL) {
        return;
    }
    char buf[1024];
    fgets(buf, sizeof(buf), fp);
    printf("Read: %s\n", buf);
    // Missing: fclose(fp);
    return;
}

int leaky_socket() {
    // VULNERABLE: socket fd is created but never close()d.
    int fd = socket(2, 1, 0);  // AF_INET, SOCK_STREAM, 0
    if (fd < 0) {
        return -1;
    }
    // ... do network operations ...
    // Missing: close(fd);
    return 0;
}

int leaky_open(const char* path) {
    // VULNERABLE: file descriptor from open() is never close()d.
    int fd = open(path, 0, 0644);
    if (fd < 0) {
        return -1;
    }
    // ... read from fd ...
    // Missing: close(fd);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }
    leaky_file_read(argv[1]);
    leaky_socket();
    leaky_open(argv[1]);
    return 0;
}
