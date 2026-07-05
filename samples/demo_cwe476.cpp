// Intentionally vulnerable sample: CWE-476 null pointer dereference.
//
// Two classic patterns:
//   1. fopen() result used without checking for NULL.
//   2. malloc() result dereferenced via * without a NULL check.
//
// A correct patch must check every allocation/open result for NULL before use.

#include <cstdio>
#include <cstdlib>
#include <cstring>

void read_config(const char* path) {
    // VULNERABLE: fopen returns NULL if the file doesn't exist, but we
    // pass it straight to fgets without checking.
    FILE* fp = fopen(path, "r");
    char line[256];
    fgets(line, sizeof(line), fp);
    printf("Config line: %s\n", line);
    fclose(fp);
}

void allocate_buffer(size_t size) {
    // VULNERABLE: malloc returns NULL on failure, but we dereference
    // the result via * without any check.
    int* buf = (int*)malloc(size * sizeof(int));
    *buf = 42;
    printf("First element: %d\n", *buf);
    free(buf);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <config-file>\n", argv[0]);
        return 1;
    }
    read_config(argv[1]);
    allocate_buffer(1024);
    return 0;
}
