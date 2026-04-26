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
        <div style={{ color: "var(--textDim)", fontSize: 14, maxWidth: 720 }}>
          Every report is structured What → Why → How. This tab pulls those into a curriculum: read the class of bug, replay the exploit, write the patch yourself.
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
        <div style={{ display: "flex", gap: 6 }}>
          {CWE_CATALOG.map(c => (
            <Btn key={c.id} primary={cweId === c.id} onClick={() => setCweId(c.id)}>{c.id} · {c.name}</Btn>
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
            <span style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--ok)", textTransform: "uppercase", letterSpacing: 1 }}>patched · {cwe.diff.split("\n").filter(l=>l.startsWith("+")).length} lines added</span>
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
  const [playing, setPlaying] = uS2(false);
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
      <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
        {CWE_CATALOG.map(c => (
          <Btn key={c.id} primary={cweId === c.id} onClick={() => { setCweId(c.id); setStep(0); setPlaying(false); }}>{c.id}</Btn>
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
const QUIZ = [
  {
    code: `def render(name):\n    return f"<h1>Hello {name}</h1>"`,
    lang: "python",
    answers: ["CWE-79", "CWE-89", "CWE-78", "no bug"],
    correct: 0,
    explain: "Direct interpolation of user input into HTML — that's reflected XSS, CWE-79. Use a templating engine that escapes by default.",
  },
  {
    code: `void copy(char *src) {\n  char dst[16];\n  memcpy(dst, src, strlen(src));\n}`,
    lang: "cpp",
    answers: ["CWE-89", "CWE-121", "CWE-78", "no bug"],
    correct: 1,
    explain: "memcpy with strlen of an attacker-controlled string and no bounds check — classic stack buffer overflow (CWE-121).",
  },
  {
    code: `cur.execute("SELECT * FROM t WHERE id = ?", (uid,))`,
    lang: "python",
    answers: ["CWE-89", "CWE-78", "CWE-79", "no bug"],
    correct: 3,
    explain: "Parameterized query, value passed as bind. The driver puts uid in the data plane — no injection possible.",
  },
];

const BugQuiz = () => {
  const [i, setI] = uS2(0);
  const [picked, setPicked] = uS2(null);
  const [score, setScore] = uS2(0);
  const q = QUIZ[i];

  const pick = (idx) => {
    if (picked !== null) return;
    setPicked(idx);
    if (idx === q.correct) setScore(s => s + 1);
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 14, fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)" }}>
        <span>question {i + 1} of {QUIZ.length}</span>
        <span>score · {score}/{i + (picked !== null ? 1 : 0)}</span>
      </div>

      <Panel padding={20}>
        <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 18, fontWeight: 600, marginBottom: 14 }}>
          What's wrong with this code?
        </div>
        <CodeBlock code={q.code} lang={q.lang} />

        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 8, marginTop: 16 }}>
          {q.answers.map((a, idx) => {
            const isPicked = picked === idx;
            const isCorrect = idx === q.correct;
            const showResult = picked !== null;
            const bg = !showResult ? "var(--panelAlt)"
                     : isCorrect ? "color-mix(in oklab, var(--ok) 18%, var(--panelAlt))"
                     : isPicked ? "color-mix(in oklab, var(--danger) 18%, var(--panelAlt))"
                     : "var(--panelAlt)";
            const border = !showResult ? "var(--border)"
                         : isCorrect ? "var(--ok)"
                         : isPicked ? "var(--danger)" : "var(--border)";
            return (
              <button key={a} onClick={() => pick(idx)} disabled={picked !== null} style={{
                padding: "12px 14px", textAlign: "left",
                background: bg, border: `1px solid ${border}`, borderRadius: 5,
                color: "var(--text)", fontFamily: "var(--fontMono)", fontSize: 13,
                cursor: picked === null ? "pointer" : "default",
                transition: "all 120ms",
              }}>
                <span style={{ color: showResult && isCorrect ? "var(--ok)" : showResult && isPicked ? "var(--danger)" : "var(--textMute)", marginRight: 8 }}>
                  {showResult && isCorrect ? "✓" : showResult && isPicked ? "✗" : String.fromCharCode(65 + idx)}
                </span>
                {a}
              </button>
            );
          })}
        </div>

        {picked !== null && (
          <div style={{ marginTop: 14, padding: 14, background: "var(--panelAlt)", border: "1px solid var(--border)", borderLeft: "3px solid var(--accent)", borderRadius: 4, fontSize: 13.5, lineHeight: 1.6, color: "var(--textDim)" }}>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--accent)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>explanation</div>
            {q.explain}
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
          {picked !== null && i < QUIZ.length - 1 && (
            <Btn primary icon="arrow" onClick={() => { setI(i + 1); setPicked(null); }}>Next question</Btn>
          )}
          {picked !== null && i === QUIZ.length - 1 && (
            <Btn primary icon="refresh" onClick={() => { setI(0); setPicked(null); setScore(0); }}>Restart · {score}/{QUIZ.length}</Btn>
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
