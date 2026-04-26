// GuardianLoop mock data — based on real CWEs in the repo
const VULN_PY = `import sqlite3
import sys

def get_user(conn, username):
    # VULNERABLE: attacker-controlled string interpolated into SQL.
    query = f"SELECT id, name, role FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()

def main():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);
        INSERT INTO users (name, role) VALUES ('alice', 'admin');
    """)
    username = sys.stdin.readline().strip()
    rows = get_user(conn, username)
    print(f"Matched {len(rows)} row(s):")
    for r in rows:
        print(r)
    if len(rows) > 1:
        print("GUARDIANLOOP_EXPLOIT_SUCCESS")
    return 0`;

const PATCHED_PY = `import sqlite3
import sys

def get_user(conn, username):
    # PATCHED: parameterized query — driver escapes the bound value.
    query = "SELECT id, name, role FROM users WHERE name = ?"
    return conn.execute(query, (username,)).fetchall()

def main():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);
        INSERT INTO users (name, role) VALUES ('alice', 'admin');
    """)
    username = sys.stdin.readline().strip()
    rows = get_user(conn, username)
    print(f"Matched {len(rows)} row(s):")
    for r in rows:
        print(r)
    if len(rows) > 1:
        print("GUARDIANLOOP_EXPLOIT_SUCCESS")
    return 0`;

const VULN_CPP = `#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

void greet(const char* user_input) {
    char buf[8];
    // VULNERABLE: no bounds check on the copy.
    strcpy(buf, user_input);
    std::printf("Hello, %s!\\n", buf);
}

int main() {
    std::string line;
    if (!std::getline(std::cin, line)) return 0;
    greet(line.c_str());
    return 0;
}`;

const PATCHED_CPP = `#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

void greet(const char* user_input) {
    char buf[8];
    // PATCHED: bounded copy + explicit null terminator.
    std::strncpy(buf, user_input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\\0';
    std::printf("Hello, %s!\\n", buf);
}

int main() {
    std::string line;
    if (!std::getline(std::cin, line)) return 0;
    greet(line.c_str());
    return 0;
}`;

const VULN_CMDI = `import os
import sys

def lookup(host):
    # VULNERABLE: attacker-controlled string passed to shell.
    os.system(f"ping -c 1 {host}")

if __name__ == "__main__":
    lookup(sys.argv[1])`;

const PATCHED_CMDI = `import subprocess
import sys

def lookup(host):
    # PATCHED: argv list, no shell interpolation.
    subprocess.run(["ping", "-c", "1", host], check=False)

if __name__ == "__main__":
    lookup(sys.argv[1])`;

const CWE_CATALOG = [
  {
    id: "CWE-89",
    name: "SQL Injection",
    severity: "CRITICAL",
    cvss: 9.8,
    language: "python",
    tool: "bandit",
    rule: "B608.hardcoded_sql_expressions",
    what: "User-controlled input is concatenated directly into a SQL query string. The database driver cannot tell the data apart from the query, so a payload like admin' OR '1'='1 changes the query's meaning.",
    why: "Once the attacker controls the WHERE clause, they can read every row, bypass authentication, exfiltrate password hashes, or in some drivers stack additional statements (DROP TABLE, INSERT). CVSS 9.8 because no auth, no UI, full confidentiality + integrity loss.",
    how: "Use parameterized queries — pass the value as a bind parameter (`?` or `$1`), never as part of the string. The driver escapes the value into the data plane and the query plane stays static.",
    cves: ["CVE-2023-32683", "CVE-2024-27286", "CVE-2025-1107"],
    vulnCode: VULN_PY,
    patchedCode: PATCHED_PY,
    exploit: "admin' OR '1'='1",
    exploitMarker: "GUARDIANLOOP_EXPLOIT_SUCCESS",
    diff: `-    query = f"SELECT id, name, role FROM users WHERE name = '{username}'"
-    return conn.execute(query).fetchall()
+    query = "SELECT id, name, role FROM users WHERE name = ?"
+    return conn.execute(query, (username,)).fetchall()`,
  },
  {
    id: "CWE-121",
    name: "Stack Buffer Overflow",
    severity: "CRITICAL",
    cvss: 9.8,
    language: "cpp",
    tool: "semgrep",
    rule: "rules.cwe-121-strcpy-no-bounds",
    what: "strcpy copies bytes from a source string into a destination buffer until it hits a null terminator — with no awareness of the destination's size. If the input is longer than the buffer, the write spills onto adjacent stack memory, including saved frame pointers and return addresses.",
    why: "On unhardened binaries, an attacker can overwrite the saved return address and redirect execution into shellcode or a ROP gadget chain. Even with stack canaries, the crash is a denial-of-service. Compiled with AddressSanitizer the overflow is deterministic — any input ≥8 bytes trips the sanitizer.",
    how: "Bound the copy: strncpy with explicit length minus one and a manual null terminator, or move to std::string / std::format. Compiler-level mitigations (FORTIFY_SOURCE, -fstack-protector-strong, ASLR) add defense in depth.",
    cves: ["CVE-2018-1125", "CVE-2021-36193", "CVE-2024-58299", "CVE-2025-4892"],
    vulnCode: VULN_CPP,
    patchedCode: PATCHED_CPP,
    exploit: "AAAAAAAAAAAAAAAAAAAAAA",
    exploitMarker: "AddressSanitizer: stack-buffer-overflow",
    diff: `-    strcpy(buf, user_input);
+    std::strncpy(buf, user_input, sizeof(buf) - 1);
+    buf[sizeof(buf) - 1] = '\\0';`,
  },
  {
    id: "CWE-78",
    name: "OS Command Injection",
    severity: "HIGH",
    cvss: 8.8,
    language: "python",
    tool: "semgrep",
    rule: "rules.cwe-78-cmdi",
    what: "User input is interpolated into a string passed to a shell (os.system, subprocess with shell=True, backticks). The shell parses metacharacters — ;, &&, $(), backticks — and the attacker's data becomes a new command.",
    why: "Payload like `host.com; cat /etc/passwd` runs both the intended ping and an arbitrary command with the application's privileges. Often the entry point for full RCE on web services that shell out to system tools.",
    how: "Pass an argv list to subprocess.run, never a string. The kernel exec call takes argv[] directly — there is no shell to interpret metacharacters. If you genuinely need a shell feature, validate input against a strict allow-list first.",
    cves: ["CVE-2023-49228", "CVE-2024-21413", "CVE-2025-22871"],
    vulnCode: VULN_CMDI,
    patchedCode: PATCHED_CMDI,
    exploit: "8.8.8.8; cat /etc/passwd",
    exploitMarker: "root:x:0:0",
    diff: `-    os.system(f"ping -c 1 {host}")
+    subprocess.run(["ping", "-c", "1", host], check=False)`,
  },
];

const CWE_BY_ID = Object.fromEntries(CWE_CATALOG.map(c => [c.id, c]));

const RECENT_RUNS = [
  { id: "20260426T121453Z", source: "samples/demo_cwe121.cpp",  language: "cpp",    findings: 1, patched: 1, status: "complete",  duration: 47, cwes: ["CWE-121"], when: "12 min ago" },
  { id: "20260426T052941Z", source: "samples/demo_cwe89.py",    language: "python", findings: 2, patched: 2, status: "complete",  duration: 38, cwes: ["CWE-89","CWE-78"], when: "1 hr ago" },
  { id: "20260426T052554Z", source: "auth/login_handler.py",    language: "python", findings: 3, patched: 2, status: "complete",  duration: 71, cwes: ["CWE-89","CWE-78","CWE-79"], when: "1 hr ago" },
  { id: "20260426T052429Z", source: "net/packet_parser.cpp",    language: "cpp",    findings: 1, patched: 0, status: "failed",    duration: 52, cwes: ["CWE-121"], when: "1 hr ago" },
  { id: "20260426T052207Z", source: "samples/demo_cwe121.cpp",  language: "cpp",    findings: 1, patched: 1, status: "complete",  duration: 41, cwes: ["CWE-121"], when: "2 hr ago" },
  { id: "20260426T051918Z", source: "ops/admin_tools.py",       language: "python", findings: 4, patched: 3, status: "complete",  duration: 89, cwes: ["CWE-78","CWE-89","CWE-22"], when: "2 hr ago" },
  { id: "20260426T050125Z", source: "samples/demo_cwe89.py",    language: "python", findings: 1, patched: 1, status: "complete",  duration: 33, cwes: ["CWE-89"], when: "3 hr ago" },
  { id: "20260425T014059Z", source: "core/string_utils.cpp",    language: "cpp",    findings: 2, patched: 1, status: "complete",  duration: 64, cwes: ["CWE-121","CWE-787"], when: "yesterday" },
];

// 14-day trend
const TREND_14D = [3,5,2,4,7,6,9,5,8,11,7,9,12,8];
const PATCHED_14D = [2,4,2,4,5,5,8,4,7,9,6,7,10,7];

const GLOSSARY = [
  { term: "SAST",    full: "Static Application Security Testing", def: "Analysis of source code without executing it. Pattern-matchers like Semgrep and Bandit walk the AST looking for known-bad shapes." },
  { term: "CWE",     full: "Common Weakness Enumeration",         def: "MITRE's catalog of software weakness categories. CWE-89 = SQL injection, CWE-121 = stack buffer overflow." },
  { term: "CVE",     full: "Common Vulnerabilities and Exposures", def: "A specific, identified flaw in a specific product. A CWE describes the class; a CVE is one instance of it in the wild." },
  { term: "CVSS",    full: "Common Vulnerability Scoring System",  def: "0.0–10.0 severity score. The vector string (AV/AC/PR/UI/S/C/I/A) shows how it was computed." },
  { term: "CoT",     full: "Chain of Thought",                     def: "Prompting technique where the LLM emits intermediate reasoning before its answer. Fixer's reasoning_chain feeds the audit report." },
  { term: "Sandbox", full: "Isolated Execution Environment",       def: "Docker container with --network=none --read-only --tmpfs /tmp --memory=512m. Red-Team runs candidate exploits inside it." },
  { term: "ASan",   full: "AddressSanitizer",                      def: "Compiler instrumentation (-fsanitize=address) that turns memory-safety bugs into deterministic crashes with stack traces." },
  { term: "NVD",    full: "National Vulnerability Database",       def: "NIST's CVE feed. Classifier hits the NVD API to map CWEs to specific CVEs and CVSS vectors." },
];

const SCAN_LOGS = [
  { agent: "scout",      level: "info",  ms:   120, msg: "semgrep loaded 47 rules from rules/" },
  { agent: "scout",      level: "info",  ms:   340, msg: "scanning samples/demo_cwe89.py (50 LOC)" },
  { agent: "scout",      level: "warn",  ms:   780, msg: "B608: hardcoded_sql_expressions @ line 19" },
  { agent: "scout",      level: "info",  ms:  1010, msg: "1 finding emitted in 0.89s" },
  { agent: "classifier", level: "info",  ms:  1240, msg: "GET https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-89" },
  { agent: "classifier", level: "info",  ms:  2160, msg: "NVD returned 47 CVEs, taking top 5 by CVSS" },
  { agent: "classifier", level: "info",  ms:  2310, msg: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL" },
  { agent: "fixer",      level: "info",  ms:  2580, msg: "→ gemini-2.5-pro: drafting patch (CoT, k=4)" },
  { agent: "fixer",      level: "debug", ms:  3220, msg: "step 1: identify the taint flow stdin → username → query" },
  { agent: "fixer",      level: "debug", ms:  4010, msg: "step 2: replace string interpolation with bind parameter" },
  { agent: "fixer",      level: "debug", ms:  4690, msg: "step 3: verify schema unchanged, semantics preserved" },
  { agent: "fixer",      level: "info",  ms:  5240, msg: "patch v1 ready (24 tokens changed)" },
  { agent: "redteam",    level: "info",  ms:  5410, msg: "docker run --network=none --read-only python-sandbox:latest" },
  { agent: "redteam",    level: "info",  ms:  5780, msg: "stdin: admin' OR '1'='1" },
  { agent: "redteam",    level: "info",  ms:  6320, msg: "exit 0 — Matched 1 row(s)" },
  { agent: "redteam",    level: "ok",    ms:  6450, msg: "exploit marker NOT found — patch holds ✓" },
  { agent: "report",     level: "info",  ms:  6610, msg: "wrote runs/20260426T121453Z/report.md" },
  { agent: "report",     level: "ok",    ms:  6720, msg: "pipeline complete in 6.72s" },
];

Object.assign(window, {
  CWE_CATALOG, CWE_BY_ID, RECENT_RUNS, TREND_14D, PATCHED_14D, GLOSSARY, SCAN_LOGS,
  VULN_PY, PATCHED_PY, VULN_CPP, PATCHED_CPP, VULN_CMDI, PATCHED_CMDI,
});
