// Intentionally vulnerable sample: CWE-457 uninitialized memory read.
//
// Two patterns:
//   1. A local buffer is declared and used as memcpy source without init.
//   2. A local int is declared, never assigned, and returned.
//
// A correct patch must initialise all variables at declaration:
//   char buf[N] = {0};  or  int result = 0;

#include <cstdio>
#include <cstring>

void leak_stack_data(char* dest, int len) {
    // VULNERABLE: 'temp' is never initialised — memcpy copies whatever
    // stale data is on the stack into 'dest'.
    char temp[128];
    memcpy(dest, temp, len);
}

int get_status() {
    // VULNERABLE: 'result' is declared but never assigned before return.
    // The caller receives indeterminate stack data.
    int result;
    return result;
}

int main() {
    char output[128];
    leak_stack_data(output, sizeof(output));

    printf("Stack data leaked: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", (unsigned char)output[i]);
    }
    printf("\n");

    int status = get_status();
    printf("Uninitialized status: %d\n", status);
    return 0;
}
