"""
Exploit harness templates. These are bind-mounted into the sandbox container
alongside the patched source file and an exploit input.

Exit-code contract (read by docker_runner.run_exploit_in_sandbox):
  42 -> exploit reproduced (patch failed)
   0 -> patch held
   3 -> compile or setup error
"""

from __future__ import annotations

from guardianloop.state import Finding


def build_exploit_input(finding: Finding) -> str:
    """Produce a malicious stdin payload appropriate to the finding's CWE."""
    cwe = finding.cwe_id
    if cwe in {"CWE-121", "CWE-787"}:
        return "A" * 1024 + "\n"
    if cwe == "CWE-89":
        return "admin' OR '1'='1\n"
    if cwe == "CWE-78":
        return "; cat /etc/passwd\n"
    if cwe == "CWE-79":
        return "<script>alert(1)</script>\n"
    return ""


def cpp_runner_script() -> str:
    """Shell script that compiles target.cpp with ASan+UBSan and feeds it the exploit input."""
    return r"""#!/bin/bash
SRC=/sandbox/target.cpp
BIN=/tmp/target

g++ -std=c++17 -fsanitize=address,undefined -fno-omit-frame-pointer -g -O0 "$SRC" -o "$BIN" 2>/tmp/compile.err
if [ $? -ne 0 ]; then
    echo "=== compile error ==="
    cat /tmp/compile.err
    echo "GUARDIANLOOP_RESULT: compile_failed"
    exit 3
fi

"$BIN" < /sandbox/exploit_input > /tmp/stdout 2> /tmp/stderr
rc=$?
cat /tmp/stdout
cat /tmp/stderr 1>&2

if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|stack-buffer-overflow|heap-buffer-overflow|global-buffer-overflow|SEGV)" /tmp/stderr; then
    echo "GUARDIANLOOP_RESULT: exploit_reproduced"
    exit 42
fi
if [ "$rc" != "0" ] && grep -qE "(Segmentation fault|core dumped|Aborted)" /tmp/stderr; then
    echo "GUARDIANLOOP_RESULT: exploit_reproduced"
    exit 42
fi
echo "GUARDIANLOOP_RESULT: patch_held"
exit 0
"""


def python_runner_script() -> str:
    """Shell script that runs target.py against the exploit input."""
    return r"""#!/bin/bash
SRC=/sandbox/target.py

python3 "$SRC" < /sandbox/exploit_input > /tmp/stdout 2> /tmp/stderr
rc=$?
cat /tmp/stdout
cat /tmp/stderr 1>&2

# The samples print GUARDIANLOOP_EXPLOIT_SUCCESS when an attack succeeds.
# A patched version of the file must not print it.
if grep -q "GUARDIANLOOP_EXPLOIT_SUCCESS" /tmp/stdout /tmp/stderr; then
    echo "GUARDIANLOOP_RESULT: exploit_reproduced"
    exit 42
fi
if [ "$rc" != "0" ] && grep -qE "(Segmentation fault|core dumped|Aborted)" /tmp/stderr; then
    echo "GUARDIANLOOP_RESULT: exploit_reproduced"
    exit 42
fi
echo "GUARDIANLOOP_RESULT: patch_held"
exit 0
"""
