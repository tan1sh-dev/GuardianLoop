// Learning tab: catalog, playground, replay, quiz, glossary
const { useState: uS2, useEffect: uE2, useRef: uR2 } = React;

const LearningScreen = () => {
  const [tab, setTab] = uS2("catalog");
  const [selectedCwe, setSelectedCwe] = uS2(null);

  // expose for navigation from outside
  uE2(() => {
    window.__openLearningCwe = (id) => { setTab("catalog"); setSelectedCwe(id); };
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div>
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--accent)", letterSpacing: 1.4, textTransform: "uppercase" }}>
          The pedagogical objective
        </div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 36, fontWeight: 600, margin: "8px 0 6px", letterSpacing: -0.6 }}>
          Learn what GuardianLoop just patched.
        </h1>
        <div style={{ display: "flex", gap: 16, marginTop: 14, marginBottom: 20, flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 220px", padding: 12, background: "var(--panelAlt)", borderLeft: "3px solid var(--accent)", borderRadius: "0 6px 6px 0" }}>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--accent)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>1. Understand (What → Why → How)</div>
            <div style={{ color: "var(--textDim)", fontSize: 12.5, lineHeight: 1.5 }}>Study the root cause, severity, real-world impact (CVEs), and secure remediations.</div>
          </div>
          <div style={{ flex: "1 1 220px", padding: 12, background: "var(--panelAlt)", borderLeft: "3px solid var(--danger)", borderRadius: "0 6px 6px 0" }}>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--danger)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>2. Replay Exploit</div>
            <div style={{ color: "var(--textDim)", fontSize: 12.5, lineHeight: 1.5 }}>Simulate active exploitation vectors inside the secure sandbox environment.</div>
          </div>
          <div style={{ flex: "1 1 220px", padding: 12, background: "var(--panelAlt)", borderLeft: "3px solid var(--ok)", borderRadius: "0 6px 6px 0" }}>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--ok)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>3. Verify Patch</div>
            <div style={{ color: "var(--textDim)", fontSize: 12.5, lineHeight: 1.5 }}>Inspect the exact diff of the AI fixer's patch successfully passing the test suite.</div>
          </div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 4, borderBottom: "1px solid var(--border)" }}>
        {[
          { id: "catalog",    label: "CWE catalog",    icon: "book" },
          { id: "playground", label: "Code playground", icon: "code" },
          { id: "replay",     label: "Replay an exploit", icon: "play" },
          { id: "quiz",       label: "Find the bug", icon: "bug" },
          { id: "glossary",   label: "Glossary",     icon: "list" },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            display: "flex", alignItems: "center", gap: 6, padding: "10px 14px",
            background: "transparent", border: "none",
            color: tab === t.id ? "var(--accent)" : "var(--textDim)",
            borderBottom: `2px solid ${tab === t.id ? "var(--accent)" : "transparent"}`,
            fontFamily: "var(--fontUI)", fontSize: 13, fontWeight: 500,
            cursor: "pointer", marginBottom: -1,
          }}>
            <Icon name={t.icon} size={13} />{t.label}
          </button>
        ))}
      </div>

      {tab === "catalog"    && <CWECatalog selectedCwe={selectedCwe} setSelectedCwe={setSelectedCwe} />}
      {tab === "playground" && <Playground />}
      {tab === "replay"     && <ExploitReplay />}
      {tab === "quiz"       && <BugQuiz />}
      {tab === "glossary"   && <GlossaryView />}
    </div>
  );
};

// ---------- Catalog ----------
const CWECatalog = ({ selectedCwe, setSelectedCwe }) => {
  const cwe = selectedCwe ? CWE_BY_ID[selectedCwe] : null;
  if (cwe) {
    return (
      <div>
        <div onClick={() => setSelectedCwe(null)} style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textDim)", cursor: "pointer", marginBottom: 12 }}>
          ← all CWEs
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
          <span style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--accent)" }}>{cwe.id}</span>
          <SeverityPill severity={cwe.severity} />
          <Tag>CVSS {cwe.cvss}</Tag>
          <Tag>{cwe.language}</Tag>
        </div>
        <h2 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 16px" }}>{cwe.name}</h2>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 18 }}>
          {[{l:"What",b:cwe.what},{l:"Why",b:cwe.why},{l:"How",b:cwe.how}].map(s => (
            <Panel key={s.l}>
              <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--accent)", textTransform: "uppercase", letterSpacing: 1.4, marginBottom: 8 }}>{s.l}</div>
              <div style={{ fontSize: 14, lineHeight: 1.65, color: "var(--textDim)" }}>{s.b}</div>
            </Panel>
          ))}
        </div>

        <Panel title="diff · the actual fix">
          <CodeBlock code={cwe.diff} lang="diff" showDiff />
        </Panel>

        <div style={{ marginTop: 14, padding: 14, background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 6 }}>
          <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>related CVEs · via NVD</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {cwe.cves.map(c => <Tag key={c} color="var(--accent2)">{c}</Tag>)}
          </div>
        </div>
      </div>
    );
  }
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14 }}>
      {CWE_CATALOG.map(c => (
        <div key={c.id} onClick={() => setSelectedCwe(c.id)} style={{
          padding: 18, background: "var(--panel)", border: "1px solid var(--border)",
          borderRadius: 6, cursor: "pointer", transition: "all 120ms",
          display: "flex", flexDirection: "column", gap: 10, minHeight: 220,
        }}
        onMouseEnter={(e) => { e.currentTarget.style.borderColor = "var(--accent)"; e.currentTarget.style.transform = "translateY(-2px)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border)"; e.currentTarget.style.transform = "translateY(0)"; }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--accent)", letterSpacing: 1 }}>{c.id}</span>
            <SeverityPill severity={c.severity} />
          </div>
          <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 22, fontWeight: 600, lineHeight: 1.2 }}>{c.name}</div>
          <div style={{ fontSize: 13, color: "var(--textDim)", lineHeight: 1.5, flex: 1 }}>{c.what.slice(0, 130)}…</div>
          <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)" }}>
            <span>{c.language} · {c.tool}</span>
            <span>cvss {c.cvss}</span>
          </div>
        </div>
      ))}
    </div>
  );
};

// ---------- Playground ----------
const Playground = () => {
  const [cweId, setCweId] = uS2("CWE-89");
  const [showPatched, setShowPatched] = uS2(false);
  const cwe = CWE_BY_ID[cweId];

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {CWE_CATALOG.map(c => (
            <Btn key={c.id} primary={cweId === c.id} onClick={() => setCweId(c.id)} style={{ fontSize: 11, padding: "6px 10px" }}>{c.id}</Btn>
          ))}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)" }}>show diff</span>
          <Toggle checked={showPatched} onChange={setShowPatched} />
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
            <Icon name="bug" size={14} style={{ color: "var(--danger)" }} />
            <span style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--danger)", textTransform: "uppercase", letterSpacing: 1 }}>vulnerable</span>
          </div>
          <CodeBlock code={cwe.vulnCode} lang={cwe.language} />
        </div>
        <div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
            <Icon name="shield" size={14} style={{ color: "var(--ok)" }} />
            <span style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--ok)", textTransform: "uppercase", letterSpacing: 1 }}>patched</span>
          </div>
          {showPatched ? <CodeBlock code={cwe.diff} lang="diff" showDiff /> : <CodeBlock code={cwe.patchedCode} lang={cwe.language} />}
        </div>
      </div>

      <Panel title="explainer · why this fix" style={{ marginTop: 14 }}>
        <div style={{ fontSize: 14, lineHeight: 1.65, color: "var(--textDim)" }}>{cwe.how}</div>
      </Panel>
    </div>
  );
};

const Toggle = ({ checked, onChange }) => (
  <button onClick={() => onChange(!checked)} style={{
    width: 36, height: 20, borderRadius: 10, position: "relative",
    background: checked ? "var(--accent)" : "var(--borderStrong)",
    border: "none", cursor: "pointer", padding: 0, transition: "background 120ms",
  }}>
    <span style={{
      position: "absolute", top: 2, left: checked ? 18 : 2, width: 16, height: 16,
      borderRadius: "50%", background: "white", transition: "left 120ms",
    }} />
  </button>
);

// ---------- Exploit Replay ----------
const ExploitReplay = () => {
  const [cweId, setCweId] = uS2("CWE-89");
  const [step, setStep] = uS2(0);
  const [playing, setPlaying] = uS2(true);
  const cwe = CWE_BY_ID[cweId];

  const steps = {
    "CWE-89": [
      { t: "stdin",    label: "attacker types payload",   detail: `admin' OR '1'='1` },
      { t: "process",  label: "f-string interpolates",    detail: `query = "SELECT … WHERE name = 'admin' OR '1'='1'"` },
      { t: "sql",      label: "sqlite parses unmodified", detail: `clause is now always-true → returns ALL rows` },
      { t: "marker",   label: "harness sees > 1 row",     detail: `prints GUARDIANLOOP_EXPLOIT_SUCCESS` },
      { t: "verdict",  label: "exit 0 · exploit reproduced", detail: `Red-Team flags this as still-vulnerable` },
    ],
    "CWE-121": [
      { t: "stdin",    label: "attacker pipes 22 bytes",  detail: `AAAAAAAAAAAAAAAAAAAAAA` },
      { t: "process",  label: "strcpy walks the source",  detail: `copies until '\\0' — no length check` },
      { t: "sql",      label: "writes past buf[8]",       detail: `clobbers stack frame, return address` },
      { t: "marker",   label: "ASan trips",               detail: `==1==ERROR: AddressSanitizer: stack-buffer-overflow` },
      { t: "verdict",  label: "exit 1 · exploit reproduced", detail: `sandbox emits the ASan banner; harness matches it` },
    ],
    "CWE-78": [
      { t: "stdin",    label: "attacker injects metachar", detail: `8.8.8.8; cat /etc/passwd` },
      { t: "process",  label: "f-string builds shell command", detail: `ping -c 1 8.8.8.8; cat /etc/passwd` },
      { t: "sql",      label: "shell parses ; as separator", detail: `runs ping THEN cat — both with app's privs` },
      { t: "marker",   label: "stdout contains /etc/passwd", detail: `root:x:0:0:root:/root:/bin/bash` },
      { t: "verdict",  label: "exit 0 · exploit reproduced", detail: `harness greps for "root:x:0:0" → match` },
    ],
    "CWE-22": [
      { t: "stdin",    label: "attacker inputs path",     detail: `../../../etc/passwd` },
      { t: "process",  label: "path joins unsafely",      detail: `filepath = "/var/www/uploads/../../../etc/passwd"` },
      { t: "fs",       label: "traverses parent root",    detail: `resolves outside upload directory boundary` },
      { t: "marker",   label: "output contains system pass", detail: `root:x:0:0:root:/root:/bin/bash` },
      { t: "verdict",  label: "exploit reproduced",       detail: `harness matches user-shadow patterns` },
    ],
    "CWE-798": [
      { t: "stdin",    label: "scans repository files",   detail: `searching code variables and static files` },
      { t: "process",  label: "credential match triggered", detail: `finds secret string: "SuperSecretDbPassword123!"` },
      { t: "auth",     label: "login with credentials",   detail: `submits credentials dynamically to login port` },
      { t: "marker",   label: "harness obtains access",   detail: `API returns successful response containing tokens` },
      { t: "verdict",  label: "credentials compromised",  detail: `static credential extraction bypasses environment config` },
    ],
    "CWE-79": [
      { t: "stdin",    label: "enters script template",   detail: `<script>alert(1)</script>` },
      { t: "process",  label: "renders greeting body",    detail: `html = "<div>Welcome back, <script>alert(1)</script>!</div>"` },
      { t: "browser",  label: "executes unescaped script", detail: `browser reads input as code rather than text` },
      { t: "marker",   label: "malicious code executes",   detail: `session data and cookies exposed` },
      { t: "verdict",  label: "XSS script parsed",        detail: `harness detects script tag trigger in active window` },
    ],
    "CWE-327": [
      { t: "stdin",    label: "extracts user hash",       detail: `MD5 password hash extracted: 098f6bcd4621d373cade4e832627b4f6` },
      { t: "process",  label: "precomputed lookups",      detail: `performs dictionary checks or MD5 reverse lookups` },
      { t: "decrypt",  label: "preimage successfully cracked", detail: `hash cracked instantly using common dictionary maps` },
      { t: "marker",   label: "reveals raw credentials",  detail: `plaintext credentials match target input` },
      { t: "verdict",  label: "vulnerable algorithm proved", detail: `insecure cryptoprimitive lacks modern work factor` },
    ],
    "CWE-601": [
      { t: "stdin",    label: "requests redirect link",   detail: `http://target.com/redirect?next=http://attacker.com` },
      { t: "process",  label: "generates redirect payload", detail: `Location: http://attacker.com` },
      { t: "browser",  label: "redirects page target",    detail: `user automatically forwarded to untrusted domain` },
      { t: "marker",   label: "phishing landing reached",  detail: `loads lookalike malicious server site` },
      { t: "verdict",  label: "unvalidated redirect holds", detail: `harness verifies destination URL changed successfully` },
    ],
    "CWE-502": [
      { t: "stdin",    label: "crafts binary string",     detail: `cos\nsystem\n(S'id'\ntR.` },
      { t: "process",  label: "loads unmarshalled packet", detail: `pickle.loads(cookie_data)` },
      { t: "exploit",  label: "deserialization executes",  detail: `executes custom OS injection on object creation` },
      { t: "marker",   label: "retrieves command response", detail: `prints execution result` },
      { t: "verdict",  label: "arbitrary code run",       detail: `harness triggers remote shell payload execution` },
    ],
    "CWE-200": [
      { t: "stdin",    label: "sends malformed query",    detail: `violates primary key validation parameters` },
      { t: "process",  label: "exception handler triggered", detail: `format_exc() constructs stack trace` },
      { t: "expose",   label: "prints traceback response", detail: `stack detail printed inside API JSON body` },
      { t: "marker",   label: "internal details leaked",  detail: `source file path and DB variables exposed` },
      { t: "verdict",  label: "system config leaked",     detail: `harness parses internal application stack structures` },
    ],
  };

  const current = steps[cweId];

  uE2(() => {
    if (!playing) return;
    if (step >= current.length - 1) { setPlaying(false); return; }
    const id = setTimeout(() => setStep(s => s + 1), 1400);
    return () => clearTimeout(id);
  }, [playing, step, cweId]);

  return (
    <div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
        {CWE_CATALOG.map(c => (
          <Btn key={c.id} primary={cweId === c.id} onClick={() => { setCweId(c.id); setStep(0); setPlaying(true); }} style={{ fontSize: 11, padding: "6px 10px" }}>{c.id}</Btn>
        ))}
        <div style={{ flex: 1 }} />
        <Btn icon="refresh" onClick={() => { setStep(0); setPlaying(false); }}>Reset</Btn>
        <Btn primary icon="play" onClick={() => { setStep(0); setPlaying(true); }}>Replay attack</Btn>
      </div>

      <Panel padding={20}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 0, marginBottom: 24, position: "relative" }}>
          <div style={{ position: "absolute", top: 17, left: "10%", right: "10%", height: 2, background: "var(--border)" }} />
          <div style={{
            position: "absolute", top: 17, left: "10%", height: 2, background: "var(--accent)",
            width: `${(step / (current.length - 1)) * 80}%`, transition: "width 600ms",
          }} />
          {current.map((s, i) => (
            <div key={i} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, position: "relative", zIndex: 1 }}>
              <div style={{
                width: 36, height: 36, borderRadius: "50%",
                background: i <= step ? "var(--accent)" : "var(--panelAlt)",
                border: `2px solid ${i <= step ? "var(--accent)" : "var(--border)"}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                color: i <= step ? "var(--bg)" : "var(--textMute)",
                fontFamily: "var(--fontMono)", fontSize: 13, fontWeight: 600,
                transition: "all 300ms",
                boxShadow: i === step ? `0 0 24px var(--accent)` : "none",
              }}>{i + 1}</div>
              <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: i <= step ? "var(--text)" : "var(--textMute)", textAlign: "center", textTransform: "uppercase", letterSpacing: 0.6 }}>{s.label}</div>
            </div>
          ))}
        </div>

        <div style={{
          background: "var(--panelAlt)", border: "1px solid var(--border)", borderRadius: 5,
          fontFamily: "var(--fontMono)", fontSize: 13, lineHeight: 1.8, padding: 16, minHeight: 220,
        }}>
          <div style={{ color: "var(--textMute)", fontSize: 10, letterSpacing: 0.6, marginBottom: 10 }}>
            $ docker run --network=none --read-only --tmpfs /tmp guardianloop/{cwe.language}-sandbox
          </div>
          {current.slice(0, step + 1).map((s, i) => (
            <div key={i} style={{ marginBottom: 10, animation: i === step ? "gl-fade 400ms" : "none" }}>
              <div style={{ color: "var(--accent)", fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>step {i + 1} · {s.label}</div>
              <div style={{ color: i === current.length - 1 && i === step ? "var(--danger)" : "var(--text)", marginTop: 4, whiteSpace: "pre-wrap" }}>
                {i === current.length - 1 && i === step ? "▌ " : "  "}{s.detail}
              </div>
            </div>
          ))}
          {step >= current.length - 1 && (
            <div style={{ marginTop: 14, padding: 10, background: "color-mix(in oklab, var(--ok) 8%, transparent)", border: "1px solid var(--ok)", borderRadius: 4, color: "var(--ok)" }}>
              ✓ This same harness, run against the patched build, returns exit 0 with no marker. Patch verified.
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
};

// ---------- Bug quiz ----------
// QUIZ_MODULES is globally loaded from quizData.jsx

const BugQuiz = () => {
  const [setupStep, setSetupStep] = uS2("difficulty"); // "difficulty" | "module" | "playing"
  const [difficulty, setDifficulty] = uS2(null);
  const [moduleKey, setModuleKey] = uS2(null);

  const [questions, setQuestions] = uS2([]);
  const [qIndex, setQIndex] = uS2(0);
  const [picked, setPicked] = uS2(null);
  
  // Gamification state
  const [score, setScore] = uS2(0);
  const [streak, setStreak] = uS2(0);
  const [timeLeft, setTimeLeft] = uS2(30);
  const [hintUsed, setHintUsed] = uS2(false);
  const hiddenAnswersRef = uR2([]);

  const resetTimer = (diff) => {
    const timeMap = { Beginner: 60, Intermediate: 30, Expert: 15 };
    setTimeLeft(timeMap[diff] || 30);
  };

  const startModule = (key) => {
    setModuleKey(key);
    const modQuestions = QUIZ_MODULES[key].questions;
    // Shuffle and pick 10 questions
    const shuffled = [...modQuestions].sort(() => 0.5 - Math.random()).slice(0, 10);
    setQuestions(shuffled);
    setQIndex(0);
    setScore(0);
    setStreak(0);
    setPicked(null);
    setHintUsed(false);
    hiddenAnswersRef.current = [];
    setSetupStep("playing");
    resetTimer(difficulty);
  };

  // Timer effect
  uE2(() => {
    if (setupStep !== "playing" || picked !== null) return;
    if (timeLeft <= 0) {
      setPicked(-1); // -1 signifies timeout
      setStreak(0);
      return;
    }
    const id = setTimeout(() => setTimeLeft(t => t - 1), 1000);
    return () => clearTimeout(id);
  }, [setupStep, picked, timeLeft]);

  const pick = (idx) => {
    if (picked !== null) return;
    setPicked(idx);
    const q = questions[qIndex];
    if (idx === q.correct) {
      setStreak(s => s + 1);
      const timeBonus = timeLeft * 2;
      const streakBonus = streak * 20;
      const points = hintUsed ? 50 : 100 + streakBonus + timeBonus;
      setScore(s => s + points);
    } else {
      setStreak(0);
    }
  };

  const nextQ = () => {
    const nextIdx = qIndex + 1;
    setQIndex(nextIdx);
    setPicked(null);
    setHintUsed(false);
    hiddenAnswersRef.current = [];
    resetTimer(difficulty);
  };

  if (setupStep === "difficulty") {
    return (
      <Panel padding={30} style={{ textAlign: "center", minHeight: 300, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center" }}>
        <Icon name="bug" size={48} style={{ color: "var(--accent)", marginBottom: 16 }} />
        <h2 style={{ fontFamily: "var(--fontDisplay)", fontSize: 24, margin: "0 0 12px" }}>GuardianLoop Challenge</h2>
        <div style={{ color: "var(--textDim)", maxWidth: 450, margin: "0 auto 24px", lineHeight: 1.6, textAlign: "center" }}>
          Select your difficulty level. This will determine how much time you have per question.
        </div>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "center" }}>
          {[
            { label: "Beginner", time: "60s/q" },
            { label: "Intermediate", time: "30s/q" },
            { label: "Expert", time: "15s/q" }
          ].map(d => (
            <Btn key={d.label} onClick={() => { setDifficulty(d.label); setSetupStep("module"); }} style={{ padding: "14px 20px" }}>
              <div style={{ fontSize: 16, fontWeight: 600 }}>{d.label}</div>
              <div style={{ fontSize: 12, color: "var(--textMute)", marginTop: 4 }}>{d.time} timer</div>
            </Btn>
          ))}
        </div>
      </Panel>
    );
  }

  if (setupStep === "module") {
    return (
      <Panel padding={30} style={{ textAlign: "center", minHeight: 300, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center" }}>
        <h2 style={{ fontFamily: "var(--fontDisplay)", fontSize: 24, margin: "0 0 12px" }}>Select a Module</h2>
        <div style={{ color: "var(--textDim)", maxWidth: 450, margin: "0 auto 24px", lineHeight: 1.6, textAlign: "center" }}>
          You've selected <span style={{ color: "var(--accent)", fontWeight: 600 }}>{difficulty}</span> difficulty. Choose a security domain to begin your 10-question challenge.
        </div>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "center" }}>
          {Object.entries(QUIZ_MODULES).map(([key, mod]) => (
            <Btn key={key} primary onClick={() => startModule(key)} style={{ padding: "14px 20px" }}>
              <div style={{ fontSize: 15, fontWeight: 600 }}>{mod.name}</div>
              <div style={{ fontSize: 12, color: "var(--bg)", opacity: 0.8, marginTop: 4 }}>10 Questions</div>
            </Btn>
          ))}
        </div>
        <div style={{ marginTop: 24 }}>
          <button onClick={() => setSetupStep("difficulty")} style={{ background: "transparent", border: "none", color: "var(--textMute)", cursor: "pointer", textDecoration: "underline", fontSize: 13 }}>
            ← Back to Difficulty
          </button>
        </div>
      </Panel>
    );
  }

  const q = questions[qIndex];
  
  const useHint = () => {
    if (hintUsed || picked !== null) return;
    const wrongs = [];
    q.answers.forEach((_, i) => { if (i !== q.correct) wrongs.push(i); });
    hiddenAnswersRef.current = wrongs.sort(() => 0.5 - Math.random()).slice(0, 2);
    setHintUsed(true);
  };

  const maxTime = { Beginner: 60, Intermediate: 30, Expert: 15 }[difficulty] || 30;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 16 }}>
        <div>
          <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>
            Question {qIndex + 1} / 10 · <span style={{ color: "var(--accent)" }}>{QUIZ_MODULES[moduleKey].name}</span>
          </div>
          <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 22, fontWeight: 600 }}>
            {q.prompt}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>
            Score
          </div>
          <div style={{ fontFamily: "var(--fontMono)", fontSize: 22, fontWeight: 600, color: "var(--accent)" }}>
            {score} <span style={{ fontSize: 16 }}>pts</span>
          </div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 16, alignItems: "center" }}>
        <div style={{ flex: 1, height: 4, background: "var(--panelAlt)", borderRadius: 2, overflow: "hidden", position: "relative" }}>
          <div style={{
            position: "absolute", top: 0, left: 0, height: "100%",
            background: timeLeft > 10 ? "var(--ok)" : "var(--danger)",
            width: `${(timeLeft / maxTime) * 100}%`, transition: "width 1s linear, background 300ms"
          }} />
        </div>
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: timeLeft <= 5 ? "var(--danger)" : "var(--text)", width: 40, textAlign: "right" }}>
          {timeLeft}s
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center", padding: "4px 10px", background: streak >= 2 ? "color-mix(in oklab, var(--danger) 15%, transparent)" : "var(--panelAlt)", borderRadius: 12, border: `1px solid ${streak >= 2 ? "var(--danger)" : "var(--border)"}` }}>
          <span style={{ fontSize: 14 }}>🔥</span>
          <span style={{ fontFamily: "var(--fontMono)", fontSize: 12, fontWeight: 600, color: streak >= 2 ? "var(--danger)" : "var(--textDim)" }}>Streak x{streak}</span>
        </div>
      </div>

      <Panel padding={0} style={{ overflow: "hidden" }}>
        <div style={{ padding: 20, borderBottom: "1px solid var(--border)" }}>
          <CodeBlock code={q.code} lang={q.lang} />
        </div>

        <div style={{ padding: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1 }}>
              Select your answer
            </div>
            {!hintUsed && picked === null && (
              <button onClick={useHint} style={{
                background: "transparent", border: "1px solid var(--accent)", color: "var(--accent)",
                padding: "4px 10px", borderRadius: 4, fontSize: 11, fontFamily: "var(--fontMono)", cursor: "pointer"
              }}>💡 Get Hint (-50% pts)</button>
            )}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: q.type === "pick_patch" ? "1fr" : "repeat(2, 1fr)", gap: 10 }}>
            {q.answers.map((a, idx) => {
              const isHidden = hiddenAnswersRef.current.includes(idx);
              if (isHidden && picked === null) {
                return (
                  <div key={idx} style={{ padding: "12px 14px", background: "var(--panelAlt)", border: "1px dashed var(--border)", borderRadius: 5, color: "var(--textMute)", opacity: 0.5, textAlign: "center", fontSize: 12, fontFamily: "var(--fontMono)" }}>
                    Eliminated
                  </div>
                );
              }

              const isPicked = picked === idx;
              const isCorrect = idx === q.correct;
              const showResult = picked !== null && (isPicked || isCorrect);
              
              const bg = (!showResult) ? "var(--panelAlt)"
                       : isCorrect ? "color-mix(in oklab, var(--ok) 18%, var(--panelAlt))"
                       : "color-mix(in oklab, var(--danger) 18%, var(--panelAlt))";
                       
              const border = (!showResult) ? "var(--border)"
                           : isCorrect ? "var(--ok)"
                           : "var(--danger)";
              
              return (
                <button key={idx} onClick={() => pick(idx)} disabled={picked !== null} style={{
                  padding: "12px 14px", textAlign: "left",
                  background: bg, border: `1px solid ${border}`, borderRadius: 5,
                  color: "var(--text)", cursor: picked === null ? "pointer" : "default",
                  transition: "all 120ms",
                }}>
                  <div style={{ display: "flex", gap: 10 }}>
                    <span style={{ color: showResult && isCorrect ? "var(--ok)" : showResult && isPicked ? "var(--danger)" : "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 13, marginTop: q.type === "pick_patch" ? 10 : 0 }}>
                      {showResult && isCorrect ? "✓" : showResult && isPicked ? "✗" : String.fromCharCode(65 + idx)}
                    </span>
                    <div style={{ flex: 1, width: "100%" }}>
                      {q.type === "pick_patch" ? (
                        <div style={{ fontFamily: "var(--fontMono)", fontSize: 12, background: "var(--bg)", padding: 10, borderRadius: 4, whiteSpace: "pre-wrap", overflowX: "auto", border: "1px solid var(--border)" }}>{a}</div>
                      ) : q.type === "identify_exploit" ? (
                        <div style={{ fontFamily: "var(--fontMono)", fontSize: 13 }}>{a}</div>
                      ) : (
                        <div style={{ fontSize: 13.5 }}>{a}</div>
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {picked !== null && (
            <div style={{ marginTop: 16, padding: 16, background: "var(--panelAlt)", border: "1px solid var(--border)", borderLeft: `3px solid ${picked === q.correct ? "var(--ok)" : "var(--danger)"}`, borderRadius: 4, animation: "gl-fade 300ms" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: picked === q.correct ? "var(--ok)" : "var(--danger)", textTransform: "uppercase", letterSpacing: 1 }}>
                  {picked === -1 ? "Timeout!" : picked === q.correct ? "Correct!" : "Incorrect"}
                </div>
                {picked === q.correct && (
                  <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--accent)" }}>
                    +{hintUsed ? 50 : 100 + (streak * 20) + (timeLeft * 2)} pts
                  </div>
                )}
              </div>
              <div style={{ fontSize: 13.5, lineHeight: 1.6, color: "var(--textDim)" }}>
                {q.explain}
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
                {qIndex < 9 ? (
                  <Btn primary icon="arrow" onClick={nextQ}>Next question</Btn>
                ) : (
                  <Btn primary icon="check" onClick={() => setSetupStep("module")}>Finish Module</Btn>
                )}
              </div>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
};

// ---------- Glossary ----------
const GlossaryView = () => (
  <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
    {GLOSSARY.map(g => (
      <Panel key={g.term}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
          <span style={{ fontFamily: "var(--fontDisplay)", fontSize: 20, fontWeight: 700, color: "var(--accent)" }}>{g.term}</span>
          <span style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)" }}>{g.full}</span>
        </div>
        <div style={{ fontSize: 13.5, color: "var(--textDim)", lineHeight: 1.6 }}>{g.def}</div>
      </Panel>
    ))}
  </div>
);

Object.assign(window, { LearningScreen });
