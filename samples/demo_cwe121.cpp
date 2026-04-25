// Intentionally vulnerable sample: CWE-121 stack-based buffer overflow.
// Used as the GuardianLoop `make demo` smoke-test target.
//
// The call to strcpy writes user-controlled input past the end of an 8-byte
// stack buffer. Compiled with AddressSanitizer in the Red-Team sandbox, any
// input longer than 7 characters deterministically triggers:
//     ==...==ERROR: AddressSanitizer: stack-buffer-overflow
//
// A correct patch must bound the copy (e.g. strncpy + explicit null terminator,
// std::string, or snprintf) so no out-of-bounds write occurs.

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

void greet(const char* user_input) {
    char buf[8];
    // VULNERABLE: no bounds check on the copy.
    strcpy(buf, user_input);
    std::printf("Hello, %s!\n", buf);
}

int main() {
    std::string line;
    if (!std::getline(std::cin, line)) {
        return 0;
    }
    greet(line.c_str());
    return 0;
}
