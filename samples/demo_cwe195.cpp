// Intentionally vulnerable sample: CWE-195 signed/unsigned comparison.
//
// A signed int from user input is used in a memory context where it gets
// implicitly converted to size_t (unsigned). If the user provides a negative
// number, the signed-to-unsigned conversion makes it an enormous positive
// value, bypassing any intended length guard.
//
// A correct patch must validate that the user-supplied value is non-negative
// before using it as a size, or use an unsigned type from the start.

#include <cstdio>
#include <cstdlib>
#include <cstring>

void process_input(const char* data, int user_len) {
    // VULNERABLE: 'user_len' is signed. If negative, (int)user_len becomes
    // a huge size_t, causing massive copy or buffer overflow.
    char output[256];
    memcpy(output, data, (int)user_len);
    output[user_len] = '\0';
    printf("Processed: %s\n", output);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <data> <length>\n", argv[0]);
        return 1;
    }
    int len = atoi(argv[2]);
    process_input(argv[1], len);
    return 0;
}
