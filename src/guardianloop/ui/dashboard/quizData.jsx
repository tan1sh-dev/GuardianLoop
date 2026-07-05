const QUIZ_MODULES = {
  web: {
    name: "Web Application Security",
    questions: [
      {
        type: "identify_cwe",
        prompt: "What's wrong with this code?",
        code: `def render(name):\n    return f"<h1>Hello {name}</h1>"`,
        lang: "python",
        answers: ["CWE-79 (XSS)", "CWE-89 (SQLi)", "CWE-78 (Command Injection)", "No Bug"],
        correct: 0,
        explain: "Direct interpolation of user input into HTML is reflected XSS (CWE-79)."
      },
      {
        type: "pick_patch",
        prompt: "Which patch securely fixes this SQL injection vulnerability?",
        code: `query = f"SELECT * FROM users WHERE username='{user}'"\ncur.execute(query)`,
        lang: "python",
        answers: [
          `query = "SELECT * FROM users WHERE username='?'"\ncur.execute(query, (user,))`,
          `query = "SELECT * FROM users WHERE username=?"\ncur.execute(query, (user,))`,
          `cur.execute("SELECT * FROM users WHERE username=" + user)`,
          `cur.execute(f"SELECT * FROM users WHERE username='{escape(user)}'")`
        ],
        correct: 1,
        explain: "Parameterized queries with bound variables (?) prevent SQL injection because the driver separates code from data."
      },
      {
        type: "identify_cwe",
        prompt: "What is the risk in this redirection handler?",
        code: `def redirect_user(target):\n    return f"HTTP/1.1 302 Found\\r\\nLocation: {target}\\r\\n\\r\\n"`,
        lang: "python",
        answers: ["CWE-79 (XSS)", "CWE-601 (Open Redirect)", "CWE-200 (Info Exposure)", "No Bug"],
        correct: 1,
        explain: "Directly passing user input into the Location header allows attackers to redirect users to malicious domains (CWE-601)."
      },
      {
        type: "identify_exploit",
        prompt: "Which payload bypasses this authentication check?",
        code: `query = f"SELECT * FROM users WHERE user='{u}' AND pass='{p}'"`,
        lang: "python",
        answers: [
          `admin' OR '1'='1`,
          `<script>alert(1)</script>`,
          `../../../../etc/passwd`,
          `127.0.0.1; whoami`
        ],
        correct: 0,
        explain: "The payload makes the WHERE clause evaluate to True regardless of the password (CWE-89)."
      },
      {
        type: "pick_patch",
        prompt: "How do you fix this XSS vulnerability in React?",
        code: `function Profile({ bio }) {\n  return <div dangerouslySetInnerHTML={{ __html: bio }} />;\n}`,
        lang: "jsx",
        answers: [
          `return <div innerHTML={bio} />;`,
          `return <div>{escape(bio)}</div>;`,
          `return <div>{bio}</div>;`,
          `return <div dangerouslySetInnerHTML={{ __html: sanitize(bio) }} />;`
        ],
        correct: 3,
        explain: "If HTML rendering is necessary, the input must be sanitized (e.g., using DOMPurify) before being set."
      },
      {
        type: "identify_cwe",
        prompt: "What vulnerability is present in this XML parser?",
        code: `import xml.etree.ElementTree as ET\ntree = ET.parse(user_upload)`,
        lang: "python",
        answers: ["CWE-611 (XXE)", "CWE-79 (XSS)", "CWE-89 (SQLi)", "No Bug"],
        correct: 0,
        explain: "Standard XML parsers may evaluate external entities (XXE), leading to local file disclosure (CWE-611)."
      },
      {
        type: "identify_exploit",
        prompt: "Which payload triggers XXE in a vulnerable parser?",
        code: `<?xml version="1.0"?>\n<data>&xxe;</data>`,
        lang: "xml",
        answers: [
          `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`,
          `<script>alert(1)</script>`,
          `' OR '1'='1`,
          `../../../../etc/passwd`
        ],
        correct: 0,
        explain: "Defining an external entity allows reading arbitrary files when the parser resolves it."
      },
      {
        type: "pick_patch",
        prompt: "Fix this insecure direct object reference (IDOR).",
        code: `def get_invoice(req):\n  invoice_id = req.args.get('id')\n  return db.query("SELECT * FROM invoices WHERE id=?", invoice_id)`,
        lang: "python",
        answers: [
          `return db.query("SELECT * FROM invoices WHERE id=?", escape(invoice_id))`,
          `return db.query("SELECT * FROM invoices WHERE id=? AND user_id=?", invoice_id, req.user.id)`,
          `return db.query(f"SELECT * FROM invoices WHERE id='{invoice_id}'")`,
          `return db.query("SELECT * FROM invoices WHERE id=? LIMIT 1", invoice_id)`
        ],
        correct: 1,
        explain: "IDOR is prevented by enforcing access control on the requested object, such as checking ownership."
      },
      {
        type: "identify_cwe",
        prompt: "What is wrong with this CORS configuration?",
        code: `app.use(cors({ origin: req.headers.origin }))`,
        lang: "javascript",
        answers: ["CWE-942 (Overly Permissive CORS)", "CWE-79 (XSS)", "CWE-352 (CSRF)", "No Bug"],
        correct: 0,
        explain: "Reflecting the Origin header back dynamically allows any domain to read authenticated responses."
      },
      {
        type: "identify_exploit",
        prompt: "Which attack exploits missing CSRF tokens?",
        code: `app.post('/transfer', (req, res) => {\n  transferFunds(req.user, req.body.to, req.body.amount);\n});`,
        lang: "javascript",
        answers: [
          `Injecting <script> into the 'to' field`,
          `A malicious site submitting a hidden form to /transfer`,
          `Sending SQL syntax in the 'amount' field`,
          `Appending ../../../ to the URL`
        ],
        correct: 1,
        explain: "Cross-Site Request Forgery (CSRF) involves a malicious site tricking the browser into making a state-changing request (CWE-352)."
      }
    ]
  },
  systems: {
    name: "Systems & Memory Safety",
    questions: [
      {
        type: "identify_cwe",
        prompt: "What vulnerability exists in this file reading function?",
        code: `def get_log(filename):\n    path = os.path.join("/var/logs", filename)\n    with open(path, "r") as f:\n        return f.read()`,
        lang: "python",
        answers: ["CWE-22 (Path Traversal)", "CWE-200 (Info Exposure)", "CWE-502 (Deserialization)", "CWE-798 (Hardcoded Creds)"],
        correct: 0,
        explain: "os.path.join resolves relative paths. An input like '../../etc/passwd' traverses outside the /var/logs boundary (CWE-22)."
      },
      {
        type: "pick_patch",
        prompt: "How do you fix this command injection?",
        code: `import os\ndef ping(host):\n  os.system(f"ping -c 1 {host}")`,
        lang: "python",
        answers: [
          `os.system("ping -c 1 " + escape(host))`,
          `os.system(f"ping -c 1 '{host}'")`,
          `subprocess.run(["ping", "-c", "1", host])`,
          `subprocess.call(f"ping -c 1 {host}", shell=True)`
        ],
        correct: 2,
        explain: "Passing the command and arguments as a list to subprocess without shell=True avoids shell evaluation entirely."
      },
      {
        type: "identify_exploit",
        prompt: "Which payload successfully exploits this endpoint?",
        code: `import os\nos.system(f"ping -c 1 {host}")`,
        lang: "python",
        answers: [
          `127.0.0.1; cat /etc/passwd`,
          `../../etc/passwd`,
          `<script>alert(1)</script>`,
          `' OR '1'='1`
        ],
        correct: 0,
        explain: "The semicolon (;) is a shell metacharacter that terminates the ping command and starts a new arbitrary command (CWE-78)."
      },
      {
        type: "identify_cwe",
        prompt: "What is wrong with this C code?",
        code: `void copy(char *src) {\n  char dst[16];\n  strcpy(dst, src);\n}`,
        lang: "c",
        answers: ["CWE-121 (Stack Buffer Overflow)", "CWE-416 (Use After Free)", "CWE-79 (XSS)", "No Bug"],
        correct: 0,
        explain: "strcpy does not check the destination buffer size, leading to a stack buffer overflow if src is larger than 16 bytes."
      },
      {
        type: "pick_patch",
        prompt: "Which patch secures this buffer copy?",
        code: `void copy(char *src) {\n  char dst[16];\n  strcpy(dst, src);\n}`,
        lang: "c",
        answers: [
          `strncpy(dst, src, 16); dst[15] = '\\0';`,
          `memcpy(dst, src, strlen(src));`,
          `sprintf(dst, "%s", src);`,
          `strcpy_s(dst, src);`
        ],
        correct: 0,
        explain: "strncpy with a bounds limit and manual null-termination ensures the buffer does not overflow."
      },
      {
        type: "identify_exploit",
        prompt: "What triggers this Use After Free vulnerability?",
        code: `char *ptr = malloc(10);\nfree(ptr);\nprintf("%s", ptr);`,
        lang: "c",
        answers: [
          `The allocation of 10 bytes`,
          `The free() call`,
          `The printf accessing a freed pointer`,
          `There is no vulnerability here`
        ],
        correct: 2,
        explain: "Accessing memory after it has been freed can lead to undefined behavior or arbitrary code execution (CWE-416)."
      },
      {
        type: "identify_cwe",
        prompt: "Identify the vulnerability in this format string.",
        code: `void log(char *msg) {\n  printf(msg);\n}`,
        lang: "c",
        answers: ["CWE-134 (Format String Injection)", "CWE-121 (Buffer Overflow)", "CWE-78 (Command Injection)", "No Bug"],
        correct: 0,
        explain: "Passing user input directly as the format string argument allows an attacker to read/write memory using %x and %n."
      },
      {
        type: "pick_patch",
        prompt: "How do you securely handle ZIP extraction?",
        code: `import zipfile\nwith zipfile.ZipFile("test.zip") as z:\n  z.extractall("/tmp/dest")`,
        lang: "python",
        answers: [
          `z.extractall("/tmp/dest", safe=True)`,
          `Iterate files and validate that path doesn't escape destination`,
          `z.extract("/tmp/dest")`,
          `Use tarfile instead of zipfile`
        ],
        correct: 1,
        explain: "zipfile's extractall is vulnerable to the Zip Slip attack (Path Traversal) unless each file's path is strictly validated."
      },
      {
        type: "identify_exploit",
        prompt: "What is a Zip Slip payload?",
        code: `# Vulnerable ZIP extraction logic`,
        lang: "python",
        answers: [
          `A file inside the ZIP named ../../../etc/passwd`,
          `A ZIP containing a malware binary`,
          `A ZIP bomb that decompresses to 100GB`,
          `A ZIP with encrypted contents`
        ],
        correct: 0,
        explain: "Zip Slip uses malicious paths inside the archive to write files outside the intended extraction directory."
      },
      {
        type: "identify_cwe",
        prompt: "What bug does this C snippet demonstrate?",
        code: `unsigned int total = item_count * item_size;\nif (total < MAX) { allocate(total); }`,
        lang: "c",
        answers: ["CWE-190 (Integer Overflow)", "CWE-121 (Buffer Overflow)", "CWE-416 (Use After Free)", "No Bug"],
        correct: 0,
        explain: "If item_count * item_size exceeds the maximum unsigned int, it wraps around (Integer Overflow), leading to a small allocation."
      }
    ]
  },
  crypto: {
    name: "Authentication & Cryptography",
    questions: [
      {
        type: "pick_patch",
        prompt: "Which is the secure way to hash a new user's password?",
        code: `import hashlib\ndef hash_pw(pw):\n    return hashlib.md5(pw.encode()).hexdigest()`,
        lang: "python",
        answers: [
          `hashlib.sha1(pw.encode()).hexdigest()`,
          `hashlib.md5((pw + "salt").encode()).hexdigest()`,
          `bcrypt.hashpw(pw.encode(), bcrypt.gensalt())`,
          `base64.b64encode(pw.encode())`
        ],
        correct: 2,
        explain: "MD5 and SHA1 are obsolete and fast to crack. Bcrypt provides a secure, slow hashing algorithm with automatic salting (CWE-327)."
      },
      {
        type: "identify_exploit",
        prompt: "Which payload triggers Remote Code Execution (RCE)?",
        code: `import pickle\ndef load_session(data):\n    return pickle.loads(data)`,
        lang: "python",
        answers: [
          `{"user": "admin", "role": "superuser"}`,
          `admin' OR '1'='1`,
          `cos\\nsystem\\n(S'id'\\ntR.`,
          `../../../../bin/bash`
        ],
        correct: 2,
        explain: "Pickle is an unsafe deserialization format. The payload constructs a Python object that calls os.system('id') during unpickling (CWE-502)."
      },
      {
        type: "identify_cwe",
        prompt: "What is wrong with this token verification?",
        code: `jwt.decode(token, verify=False)`,
        lang: "python",
        answers: ["CWE-345 (Insufficient Verification)", "CWE-79 (XSS)", "CWE-89 (SQLi)", "No Bug"],
        correct: 0,
        explain: "Decoding a JWT without verifying its signature allows attackers to forge tokens with any claims they want."
      },
      {
        type: "pick_patch",
        prompt: "Fix this insecure pseudorandom number generator for tokens.",
        code: `import random\ntoken = hex(random.getrandbits(128))`,
        lang: "python",
        answers: [
          `token = hex(random.getrandbits(256))`,
          `import secrets\ntoken = secrets.token_hex(16)`,
          `token = hashlib.md5(str(random.random()).encode()).hexdigest()`,
          `token = str(random.randint(0, 999999999))`
        ],
        correct: 1,
        explain: "The 'random' module is not cryptographically secure. The 'secrets' module should be used for security-sensitive tokens (CWE-338)."
      },
      {
        type: "identify_cwe",
        prompt: "What vulnerability exists in this API?",
        code: `AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\nAWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
        lang: "python",
        answers: ["CWE-798 (Hardcoded Credentials)", "CWE-200 (Info Exposure)", "CWE-22 (Path Traversal)", "No Bug"],
        correct: 0,
        explain: "Hardcoding secrets in source code leads to massive compromises if the repository is leaked or accessed by unauthorized users."
      },
      {
        type: "identify_exploit",
        prompt: "How can an attacker exploit an Electronic Codebook (ECB) cipher?",
        code: `cipher = AES.new(key, AES.MODE_ECB)`,
        lang: "python",
        answers: [
          `By injecting shell commands into the ciphertext`,
          `By comparing identical plaintext blocks which produce identical ciphertext blocks`,
          `By overflowing the encryption buffer`,
          `By sending an SQL injection in the key`
        ],
        correct: 1,
        explain: "ECB mode is deterministic. Identical plaintext blocks encrypt to identical ciphertext blocks, revealing patterns (e.g., the ECB Penguin)."
      },
      {
        type: "pick_patch",
        prompt: "Secure this timing-attack vulnerable string comparison.",
        code: `if user_token == actual_token:\n  grant_access()`,
        lang: "python",
        answers: [
          `if str(user_token) == str(actual_token): grant_access()`,
          `if hashlib.md5(user_token) == hashlib.md5(actual_token): grant_access()`,
          `import hmac\nif hmac.compare_digest(user_token, actual_token): grant_access()`,
          `if user_token.startswith(actual_token): grant_access()`
        ],
        correct: 2,
        explain: "Standard string comparison fails at the first mismatched character, leaking length/timing. hmac.compare_digest uses a constant-time comparison."
      },
      {
        type: "identify_cwe",
        prompt: "What is wrong with this password storage?",
        code: `hash = hashlib.sha256(password.encode()).hexdigest()\ndb.save(hash)`,
        lang: "python",
        answers: ["CWE-327 (Weak Crypto)", "CWE-759 (Hash Without Salt)", "CWE-89 (SQLi)", "No Bug"],
        correct: 1,
        explain: "Using a fast hash function like SHA-256 without a unique salt allows attackers to use precomputed rainbow tables (CWE-759)."
      },
      {
        type: "identify_exploit",
        prompt: "What is the danger of a padded oracle attack?",
        code: `cipher = AES.new(key, AES.MODE_CBC, iv)`,
        lang: "python",
        answers: [
          `It decrypts ciphertext by observing padding error responses`,
          `It executes arbitrary code via the padding`,
          `It bypasses authentication checks`,
          `It leaks the encryption key`
        ],
        correct: 0,
        explain: "If an application leaks whether ciphertext decryption padding was valid (e.g. via HTTP 500 vs 200), attackers can decrypt the entire ciphertext."
      },
      {
        type: "pick_patch",
        prompt: "How do you securely configure this cookie?",
        code: `res.cookie('session_id', token)`,
        lang: "javascript",
        answers: [
          `res.cookie('session_id', token, { secure: true })`,
          `res.cookie('session_id', token, { httpOnly: true })`,
          `res.cookie('session_id', token, { httpOnly: true, secure: true, sameSite: 'strict' })`,
          `res.cookie('session_id', token, { maxAge: 3600 })`
        ],
        correct: 2,
        explain: "Cookies holding session tokens should always be flagged HttpOnly (prevents XSS), Secure (HTTPS only), and SameSite (prevents CSRF)."
      }
    ]
  }
};

Object.assign(window, { QUIZ_MODULES });
