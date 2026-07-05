# Intentionally vulnerable sample: CWE-95 unsafe eval/exec.
#
# eval() and exec() on user-supplied strings allow arbitrary code execution.
# An attacker can pass: __import__('os').system('whoami')
#
# A correct patch must remove eval/exec entirely and use ast.literal_eval()
# for safe data parsing, or restructure the logic.

import sys


def calculator(expression):
    # VULNERABLE: user input passed directly to eval()
    result = eval(expression)
    return result


def run_user_code(code_string):
    # VULNERABLE: user input passed directly to exec()
    exec(code_string)


if __name__ == "__main__":
    user_expr = input("Enter a math expression: ")
    print(f"Result: {calculator(user_expr)}")

    user_code = input("Enter Python code to run: ")
    run_user_code(user_code)
