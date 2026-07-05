// Intentionally vulnerable sample: CWE-369 division by zero via atoi().
//
// User-supplied input is converted with atoi() and used directly as a
// divisor without checking for zero. Passing "0" as the argument causes
// undefined behaviour (typically SIGFPE / crash).
//
// A correct patch must validate that the denominator is non-zero before
// performing the division.

#include <cstdio>
#include <cstdlib>

int compute_average(int total, const char* count_str) {
    // VULNERABLE: atoi("0") returns 0, causing division by zero.
    int count = atoi(count_str);
    int average = total / count;
    return average;
}

int compute_remainder(int value, const char* divisor_str) {
    // VULNERABLE: strtol("0", ...) returns 0, causing modulo by zero.
    int divisor = strtol(divisor_str, NULL, 10);
    int remainder = value % divisor;
    return remainder;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <total> <count>\n", argv[0]);
        return 1;
    }
    int total = atoi(argv[1]);
    int avg = compute_average(total, argv[2]);
    printf("Average: %d\n", avg);

    int rem = compute_remainder(total, argv[2]);
    printf("Remainder: %d\n", rem);
    return 0;
}
