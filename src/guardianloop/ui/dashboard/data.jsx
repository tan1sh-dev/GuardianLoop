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

const VULN_PATHTRAV = `import os

def read_file(filename):
    # VULNERABLE: concatenates paths without verifying boundaries
    filepath = os.path.join("/var/www/uploads", filename)
    with open(filepath, "r") as f:
        return f.read()`;

const PATCHED_PATHTRAV = `from pathlib import Path

def read_file(filename):
    # PATCHED: resolve target path and verify it stays inside base
    base = Path("/var/www/uploads").resolve()
    target = (base / filename).resolve()
    if not target.is_relative_to(base):
        raise ValueError("Access Denied: Path Traversal Detected")
    with open(target, "r") as f:
        return f.read()`;

const VULN_CREDS = `def connect_to_database():
    # VULNERABLE: hardcoded sensitive database password
    db_password = "SuperSecretDbPassword123!"
    return authenticate_db(user="admin", password=db_password)`;

const PATCHED_CREDS = `import os

def connect_to_database():
    # PATCHED: dynamic loading from environment variables
    db_password = os.environ.get("DATABASE_PASSWORD")
    if not db_password:
        raise ValueError("DATABASE_PASSWORD environment variable not set")
    return authenticate_db(user="admin", password=db_password)`;

const VULN_XSS = `def render_greeting(username):
    # VULNERABLE: directly interpolating user input in HTML
    return f"<div>Welcome back, {username}!</div>"`;

const PATCHED_XSS = `import html

def render_greeting(username):
    # PATCHED: secure HTML escaping to prevent XSS payloads
    safe_username = html.escape(username)
    return f"<div>Welcome back, {safe_username}!</div>"`;

const VULN_CRYPTO = `import hashlib

def generate_hash(password):
    # VULNERABLE: using obsolete and weak MD5 hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()`;

const PATCHED_CRYPTO = `import bcrypt

def generate_hash(password):
    # PATCHED: secure, slow hashing algorithm with automatic salt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()`;

const VULN_REDIRECT = `def handle_redirect(next_url):
    # VULNERABLE: unsafely redirects to any user-provided URL
    return f"HTTP/1.1 302 Found\\r\\nLocation: {next_url}\\r\\n\\r\\n"`;

const PATCHED_REDIRECT = `from urllib.parse import urlparse

def handle_redirect(next_url, allowed_hosts={"example.com"}):
    # PATCHED: parse destination URL and restrict to allowed hosts
    parsed = urlparse(next_url)
    host = parsed.netloc or parsed.path.split("/")[0]
    if host and host not in allowed_hosts:
        raise ValueError("Security Error: External redirection unauthorized")
    return f"HTTP/1.1 302 Found\\r\\nLocation: {next_url}\\r\\n\\r\\n"`;

const VULN_DESER = `import pickle

def load_user_session(cookie_data):
    # VULNERABLE: pickle.loads deserializes dangerous code executions
    return pickle.loads(cookie_data)`;

const PATCHED_DESER = `import json

def load_user_session(cookie_data):
    # PATCHED: parse standard structured JSON string safely
    return json.loads(cookie_data.decode())`;

const VULN_INFO = `import traceback

def get_profile():
    try:
        fetch_db_records()
    except Exception as e:
        # VULNERABLE: exposing internal execution stack trace to users
        return {"status": "error", "details": traceback.format_exc()}`;

const PATCHED_INFO = `import logging

def get_profile():
    try:
        fetch_db_records()
    except Exception as e:
        # PATCHED: log full details internally and return a generic error message
        logging.error("Failed to fetch user profiles", exc_info=True)
        return {"status": "error", "details": "An internal database error occurred"}`;


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
  {
    id: "CWE-22",
    name: "Path Traversal",
    severity: "HIGH",
    cvss: 7.5,
    language: "python",
    tool: "semgrep",
    rule: "rules.cwe-22-path-traversal",
    what: "An application builds file paths dynamically using user input (filenames, folder paths) without verifying that the resolved path stays inside the target directory. Attackers insert directory traversal characters (e.g. '../') to escape base folders.",
    why: "It permits reading or overwriting sensitive application configuration files, user data, server credentials, or operating system system logs (like /etc/passwd).",
    how: "Resolve targets dynamically using Python's Pathlib. Convert paths to absolute using target.resolve() and verify boundaries via target.is_relative_to(base).",
    cves: ["CVE-2023-3824", "CVE-2024-23334"],
    vulnCode: VULN_PATHTRAV,
    patchedCode: PATCHED_PATHTRAV,
    exploit: "../../../etc/passwd",
    exploitMarker: "Access Denied: Path Traversal",
    diff: `-    filepath = os.path.join("/var/www/uploads", filename)
-    with open(filepath, "r") as f:
+    base = Path("/var/www/uploads").resolve()
+    target = (base / filename).resolve()
+    if not target.is_relative_to(base):
+        raise ValueError("Access Denied: Path Traversal Detected")
+    with open(target, "r") as f:`,
  },
  {
    id: "CWE-798",
    name: "Use of Hardcoded Credentials",
    severity: "HIGH",
    cvss: 8.9,
    language: "python",
    tool: "semgrep",
    rule: "rules.cwe-798-hardcoded-credentials",
    what: "Sensitive configuration values (API keys, secret tokens, database credentials, passwords) are directly committed inside the source code files. Because source code is often shared, stored in git history, or easily decompiled, these secrets are easily leaked.",
    why: "Hardcoded credentials cannot be easily rotated without deploying code changes, and any compromise of code repositories instantly leaks administrative access.",
    how: "Store configurations dynamically outside of code. Use standard environment variables (os.environ) or secrets managers, and load values at run-time.",
    cves: ["CVE-2021-39132", "CVE-2023-28840"],
    vulnCode: VULN_CREDS,
    patchedCode: PATCHED_CREDS,
    exploit: "Dump git history / grep code",
    exploitMarker: "SuperSecretDbPassword123!",
    diff: `-    db_password = "SuperSecretDbPassword123!"
+    db_password = os.environ.get("DATABASE_PASSWORD")
+    if not db_password:
+        raise ValueError("DATABASE_PASSWORD environment variable not set")`,
  },
  {
    id: "CWE-79",
    name: "Cross-Site Scripting (XSS)",
    severity: "HIGH",
    cvss: 8.0,
    language: "python",
    tool: "semgrep",
    rule: "rules.cwe-79-xss",
    what: "Unescaped and unsanitized user-supplied strings are printed directly into active HTML documents. Browsers run malicious JavaScript tags injected by attackers.",
    why: "Enables arbitrary execution of client scripts, allowing attackers to hijack session cookies, deface layouts, steal sensitive user data, or redirect to malicious landing domains.",
    how: "Always HTML-encode any dynamic inputs printed in HTML contexts using libraries like Python's 'html' module (html.escape) or secure template engines with auto-escaping (Jinja2).",
    cves: ["CVE-2023-45811", "CVE-2024-21626"],
    vulnCode: VULN_XSS,
    patchedCode: PATCHED_XSS,
    exploit: "<script>alert(1)</script>",
    exploitMarker: "&lt;script&gt;alert(1)&lt;/script&gt;",
    diff: `-    return f"<div>Welcome back, {username}!</div>"
+    safe_username = html.escape(username)
+    return f"<div>Welcome back, {safe_username}!</div>"`,
  },
  {
    id: "CWE-327",
    name: "Broken Cryptographic Algorithm",
    severity: "MEDIUM",
    cvss: 5.9,
    language: "python",
    tool: "semgrep",
    rule: "rules.cwe-327-weak-hashes",
    what: "The application relies on obsolete and mathematically insecure cryptographic hash algorithms (like MD5 or SHA1) for credential storage, digital signatures, or verification checks.",
    why: "These legacy hash algorithms suffer from severe collision vulnerability risks and are easily cracked using precomputed rainbow tables or basic modern hardware.",
    how: "Transition critical credential systems to secure, modern password hashing primitives such as Bcrypt, Argon2, or PBKDF2 that integrate random salts and workload factors.",
    cves: ["CVE-2022-24723", "CVE-2024-34064"],
    vulnCode: VULN_CRYPTO,
    patchedCode: PATCHED_CRYPTO,
    exploit: "rainbow_table_crack",
    exploitMarker: "$2b$12$",
    diff: `-    return hashlib.md5(password.encode()).hexdigest()
+    salt = bcrypt.gensalt()
+    return bcrypt.hashpw(password.encode(), salt).decode()`,
  },
  {
    id: "CWE-601",
    name: "Open Redirect",
    severity: "MEDIUM",
    cvss: 6.1,
    language: "python",
    tool: "semgrep",
    rule: "rules.cwe-601-open-redirect",
    what: "An application redirects browser sessions based on a parameter input (e.g. ?next=http://attacker.com) without validating the host, leading users to phishing websites.",
    why: "Attackers exploit user trust by providing a legitimate starting URL and silently redirecting them to identical-looking credential harvesting domains.",
    how: "Always parse redirect targets using urlparse. Restrict allowed targets to absolute local paths (starting with '/') or pre-approved safe domains.",
    cves: ["CVE-2023-28858", "CVE-2024-22120"],
    vulnCode: VULN_REDIRECT,
    patchedCode: PATCHED_REDIRECT,
    exploit: "http://attacker-controlled.site",
    exploitMarker: "Security Error: External redirection unauthorized",
    diff: `-    return f"HTTP/1.1 302 Found\\r\\nLocation: {next_url}\\r\\n\\r\\n"
+    parsed = urlparse(next_url)
+    host = parsed.netloc or parsed.path.split("/")[0]
+    if host and host not in allowed_hosts:
+        raise ValueError("Security Error: External redirection unauthorized")
+    return f"HTTP/1.1 302 Found\\r\\nLocation: {next_url}\\r\\n\\r\\n"`,
  },
  {
    id: "CWE-502",
    name: "Insecure Deserialization",
    severity: "CRITICAL",
    cvss: 9.8,
    language: "python",
    tool: "semgrep",
    rule: "rules.cwe-502-deserialization",
    what: "Parsing untrusted serialized streams into in-memory objects. Python's pickle library executes embedded payload commands during deserialization.",
    why: "Enables instant, direct Remote Code Execution (RCE) on servers whenever they parse attacker-crafted sessions, cookies, or payload variables.",
    how: "Avoid deserializing untrusted binary streams. Rely on standard schema-enforced, pure data formats such as JSON or Protocol Buffers.",
    cves: ["CVE-2023-30547", "CVE-2024-24576"],
    vulnCode: VULN_DESER,
    patchedCode: PATCHED_DESER,
    exploit: "cos\nsystem\n(S'id'\ntR.",
    exploitMarker: "json.decoder.JSONDecodeError",
    diff: `-    return pickle.loads(cookie_data)
+    return json.loads(cookie_data.decode())`,
  },
  {
    id: "CWE-200",
    name: "Exposure of Sensitive Information",
    severity: "MEDIUM",
    cvss: 5.3,
    language: "python",
    tool: "semgrep",
    rule: "rules.cwe-200-debug-exposure",
    what: "The system returns internal stack traces, sql connection properties, environment configurations, or file paths directly inside customer-facing API responses.",
    why: "It exposes valuable implementation details (database technology, framework versions, configuration properties) that help attackers craft precise exploits.",
    how: "Catch exceptions cleanly, write full debug logs locally on the secure server, and return generic, sanitized system errors to public API consumers.",
    cves: ["CVE-2023-22485", "CVE-2024-29025"],
    vulnCode: VULN_INFO,
    patchedCode: PATCHED_INFO,
    exploit: "Trigger Exception",
    exploitMarker: "An internal database error occurred",
    diff: `-        return {"status": "error", "details": traceback.format_exc()}
+        logging.error("Failed to fetch user profiles", exc_info=True)
+        return {"status": "error", "details": "An internal database error occurred"}`,
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
  { term: "DAST",    full: "Dynamic Application Security Testing", def: "Testing a running application by sending active payloads/exploits to verify if vulnerabilities are exploitable from the outside." },
  { term: "SCA",     full: "Software Composition Analysis",        def: "Scanning project dependencies (like package.json, requirements.txt) to identify outdated or vulnerable third-party libraries." },
  { term: "RCE",     full: "Remote Code Execution",                def: "The highest-severity impact where an attacker executes arbitrary code or shell commands on the target host." },
  { term: "SSRF",    full: "Server-Side Request Forgery",          def: "Abusing server functionality to force the back-end to make requests to internal or external network resources on behalf of the attacker." },
  { term: "SQLi",    full: "SQL Injection",                        def: "Untrusted user inputs contaminating a SQL query, allowing attackers to manipulate queries and bypass authentication or read/write DB data." },
  { term: "XSS",     full: "Cross-Site Scripting",                 def: "Injecting malicious scripts into otherwise benign and trusted websites, which then execute in the context of a victim's browser." },
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
