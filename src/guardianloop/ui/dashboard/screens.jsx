// Overview, Findings, Scan Detail, New Scan, Settings
const { useState: uS1, useEffect: uE1 } = React;

// ========== OVERVIEW ==========
const OverviewScreen = ({ onNav }) => {
  const totalFindings = RECENT_RUNS.reduce((a, r) => a + r.findings, 0);
  const totalPatched = RECENT_RUNS.reduce((a, r) => a + r.patched, 0);
  const patchRate = ((totalPatched / totalFindings) * 100).toFixed(0);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div>
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", letterSpacing: 1.4, textTransform: "uppercase" }}>
          Mission control
        </div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 36, fontWeight: 600, margin: "8px 0 6px", letterSpacing: -0.6 }}>
          Good morning. <span style={{ color: "var(--textDim)" }}>3 critical findings auto-patched overnight.</span>
        </h1>
        <div style={{ color: "var(--textDim)", fontSize: 14 }}>
          Pipeline ran 8 times in the last 24h · avg duration 54s · {patchRate}% patch hold rate
        </div>
      </div>

      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        <KPICard label="findings · 14d" value={totalFindings} delta="+18%" trend={TREND_14D} color="var(--accent)" />
        <KPICard label="patches held"   value={totalPatched} delta={`${patchRate}%`} trend={PATCHED_14D} color="var(--ok)" />
        <KPICard label="avg cvss"       value="8.4" delta="critical" trend={[6,7,7,8,8,9,8,9,9,8,9,8,9,8]} color="var(--danger)" />
        <KPICard label="loop iterations" value="1.4" delta="avg/run" trend={[1,2,1,1,2,3,1,2,1,1,2,1,2,1]} color="var(--accent2)" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
        {/* Recent runs */}
        <Panel title="recent runs" action={
          <Btn ghost icon="arrow" onClick={() => onNav("scans")}>view all</Btn>
        }>
          <div style={{ display: "grid", gap: 1, background: "var(--border)", border: "1px solid var(--border)", borderRadius: 4 }}>
            {RECENT_RUNS.slice(0, 6).map(r => (
              <div key={r.id} onClick={() => onNav("detail", r)} style={{
                display: "grid", gridTemplateColumns: "auto 1.5fr auto auto auto auto",
                gap: 12, alignItems: "center", padding: "10px 14px",
                background: "var(--panel)", cursor: "pointer",
                fontSize: 13,
              }}>
                <StatusDot status={r.status} />
                <div style={{ overflow: "hidden" }}>
                  <div style={{ fontFamily: "var(--fontMono)", color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.source}</div>
                  <div style={{ fontFamily: "var(--fontMono)", fontSize: 10.5, color: "var(--textMute)", marginTop: 2 }}>{r.id} · {r.when}</div>
                </div>
                <div style={{ display: "flex", gap: 4 }}>
                  {r.cwes.map(c => <Tag key={c} color="var(--textDim)">{c}</Tag>)}
                </div>
                <div style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)" }}>
                  <span style={{ color: "var(--ok)" }}>{r.patched}</span>
                  <span style={{ color: "var(--textMute)" }}> / </span>
                  {r.findings}
                </div>
                <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)" }}>{r.duration}s</div>
                <Icon name="chevron" size={14} />
              </div>
            ))}
          </div>
        </Panel>

        {/* Quick actions + agent status */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <Panel title="quick start">
            <div style={{ display: "grid", gap: 8 }}>
              <Btn primary icon="play" onClick={() => onNav("live")}>Start a new scan</Btn>
              <Btn icon="upload" onClick={() => onNav("new")}>Upload code</Btn>
              <Btn icon="git" onClick={() => onNav("new")}>Scan a GitHub PR</Btn>
            </div>
          </Panel>
          <Panel title="agent health">
            {AGENTS.map(a => (
              <div key={a.id} style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "7px 0", fontSize: 12.5,
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Icon name={a.icon} size={14} />
                  <span style={{ fontFamily: "var(--fontMono)" }}>{a.label}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--ok)" }}>
                  <StatusDot status="complete" /> ready
                </div>
              </div>
            ))}
          </Panel>
        </div>
      </div>

      {/* CWE breakdown */}
      <Panel title="top weakness classes · 14 days">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
          {CWE_CATALOG.map(c => (
            <div key={c.id} onClick={() => onNav("learning", c.id)} style={{
              padding: 14, background: "var(--panelAlt)", border: "1px solid var(--border)",
              borderRadius: 5, cursor: "pointer", transition: "border-color 120ms",
            }}
            onMouseEnter={(e) => e.currentTarget.style.borderColor = "var(--accent)"}
            onMouseLeave={(e) => e.currentTarget.style.borderColor = "var(--border)"}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <span style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--accent)" }}>{c.id}</span>
                <SeverityPill severity={c.severity} />
              </div>
              <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 15, fontWeight: 600 }}>{c.name}</div>
              <div style={{ fontSize: 12, color: "var(--textDim)", marginTop: 6, lineHeight: 1.5 }}>
                {c.what.slice(0, 90)}…
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10, fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)" }}>
                <span>{c.tool}</span><span>cvss {c.cvss}</span>
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
};

const KPICard = ({ label, value, delta, trend, color }) => (
  <div style={{
    padding: 14, background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 6,
  }}>
    <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
    <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: 8, marginBottom: 6 }}>
      <span style={{ fontFamily: "var(--fontDisplay)", fontSize: 28, fontWeight: 600, lineHeight: 1 }}>{value}</span>
      <span style={{ fontFamily: "var(--fontMono)", fontSize: 11, color }}>{delta}</span>
    </div>
    <Sparkline data={trend} w={200} h={28} color={color} />
  </div>
);

// ========== FINDINGS LIBRARY ==========
const ALL_FINDINGS = [
  { id: "f1", run: "20260426T121453Z", file: "samples/demo_cwe121.cpp",  line: 20, cwe: "CWE-121", severity: "CRITICAL", cvss: 9.8, status: "patched",     tool: "semgrep" },
  { id: "f2", run: "20260426T052941Z", file: "samples/demo_cwe89.py",    line: 19, cwe: "CWE-89",  severity: "CRITICAL", cvss: 9.8, status: "patched",     tool: "bandit" },
  { id: "f3", run: "20260426T052941Z", file: "samples/demo_cwe89.py",    line: 41, cwe: "CWE-78",  severity: "HIGH",     cvss: 8.8, status: "patched",     tool: "semgrep" },
  { id: "f4", run: "20260426T052554Z", file: "auth/login_handler.py",    line: 84, cwe: "CWE-89",  severity: "CRITICAL", cvss: 9.8, status: "patched",     tool: "bandit" },
  { id: "f5", run: "20260426T052554Z", file: "auth/login_handler.py",    line:128, cwe: "CWE-78",  severity: "HIGH",     cvss: 8.4, status: "patched",     tool: "semgrep" },
  { id: "f6", run: "20260426T052554Z", file: "auth/login_handler.py",    line:217, cwe: "CWE-79",  severity: "MEDIUM",   cvss: 6.1, status: "exploitable", tool: "semgrep" },
  { id: "f7", run: "20260426T052429Z", file: "net/packet_parser.cpp",    line: 92, cwe: "CWE-121", severity: "CRITICAL", cvss: 9.8, status: "exploitable", tool: "semgrep" },
  { id: "f8", run: "20260426T051918Z", file: "ops/admin_tools.py",       line: 56, cwe: "CWE-78",  severity: "HIGH",     cvss: 8.8, status: "patched",     tool: "semgrep" },
  { id: "f9", run: "20260426T051918Z", file: "ops/admin_tools.py",       line: 71, cwe: "CWE-89",  severity: "CRITICAL", cvss: 9.1, status: "patched",     tool: "bandit" },
  { id: "f10",run: "20260426T051918Z", file: "ops/admin_tools.py",       line:103, cwe: "CWE-22",  severity: "HIGH",     cvss: 7.5, status: "patched",     tool: "semgrep" },
  { id: "f11",run: "20260426T051918Z", file: "ops/admin_tools.py",       line:188, cwe: "CWE-78",  severity: "HIGH",     cvss: 8.8, status: "exploitable", tool: "semgrep" },
  { id: "f12",run: "20260425T014059Z", file: "core/string_utils.cpp",    line: 33, cwe: "CWE-121", severity: "CRITICAL", cvss: 9.8, status: "patched",     tool: "semgrep" },
  { id: "f13",run: "20260425T014059Z", file: "core/string_utils.cpp",    line: 67, cwe: "CWE-787", severity: "HIGH",     cvss: 8.1, status: "exploitable", tool: "semgrep" },
];

const FindingsScreen = ({ onNav }) => {
  const [filter, setFilter] = uS1("all");
  const [q, setQ] = uS1("");
  const filtered = ALL_FINDINGS.filter(f => {
    if (filter !== "all" && f.status !== filter) return false;
    if (q && !`${f.file} ${f.cwe}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 4px" }}>Findings library</h1>
        <div style={{ color: "var(--textDim)" }}>{ALL_FINDINGS.length} total findings across {RECENT_RUNS.length} runs</div>
      </div>

      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, flex: 1, padding: "8px 12px", background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 5 }}>
          <Icon name="search" size={14} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="filter by file or CWE…"
            style={{ background: "none", border: "none", outline: "none", color: "var(--text)", fontFamily: "var(--fontMono)", fontSize: 13, width: "100%" }} />
        </div>
        {["all", "patched", "exploitable"].map(f => (
          <Btn key={f} primary={filter === f} onClick={() => setFilter(f)}>{f}</Btn>
        ))}
        <Btn icon="download">export csv</Btn>
      </div>

      <div style={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
        <div style={{
          display: "grid", gridTemplateColumns: "auto 80px 2fr 70px 80px 110px 80px 24px",
          gap: 12, padding: "10px 14px", borderBottom: "1px solid var(--border)",
          fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 0.8,
        }}>
          <span>sev</span><span>cwe</span><span>file</span><span>line</span><span>tool</span><span>cvss</span><span>status</span><span></span>
        </div>
        {filtered.map(f => (
          <div key={f.id} onClick={() => onNav("learning", f.cwe)} style={{
            display: "grid", gridTemplateColumns: "auto 80px 2fr 70px 80px 110px 80px 24px",
            gap: 12, padding: "10px 14px", borderBottom: "1px solid var(--border)",
            fontFamily: "var(--fontMono)", fontSize: 12, alignItems: "center", cursor: "pointer",
          }}>
            <SeverityPill severity={f.severity} />
            <span style={{ color: "var(--accent)" }}>{f.cwe}</span>
            <span style={{ color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.file}</span>
            <span style={{ color: "var(--textDim)" }}>:{f.line}</span>
            <span style={{ color: "var(--textDim)" }}>{f.tool}</span>
            <span>
              <span style={{
                width: `${f.cvss * 10}%`, height: 4, display: "inline-block",
                background: f.cvss >= 9 ? "var(--danger)" : f.cvss >= 7 ? "var(--warn)" : "var(--info)",
                marginRight: 6, verticalAlign: "middle",
              }} />
              <span style={{ color: "var(--textDim)" }}>{f.cvss}</span>
            </span>
            <span style={{ color: f.status === "patched" ? "var(--ok)" : "var(--danger)" }}>● {f.status}</span>
            <Icon name="chevron" size={12} />
          </div>
        ))}
      </div>
    </div>
  );
};

// ========== SCAN DETAIL ==========
const ScanDetailScreen = ({ run, onNav }) => {
  const cwe = CWE_BY_ID["CWE-89"];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div onClick={() => onNav("overview")} style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textDim)", cursor: "pointer", marginBottom: 4 }}>
            ← all runs
          </div>
          <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 30, fontWeight: 600, margin: 0 }}>
            {(run && run.source) || "samples/demo_cwe89.py"}
          </h1>
          <div style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)", marginTop: 4 }}>
            {(run && run.id) || "20260426T121453Z"} · python · 50 LOC · 6.72s · 1 finding · 1 patch held
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn icon="download">report.md</Btn>
          <Btn icon="download">findings.json</Btn>
          <Btn primary icon="refresh">re-run</Btn>
        </div>
      </div>

      {/* finding card with what/why/how */}
      <Panel title={`finding 1 of 1 · ${cwe.id}`}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 16, marginBottom: 16 }}>
          <div>
            <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 22, fontWeight: 600, marginBottom: 6 }}>{cwe.name}</div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              <Tag color="var(--accent)">{cwe.id}</Tag>
              {cwe.cves.slice(0, 3).map(c => <Tag key={c}>{c}</Tag>)}
              <Tag color="var(--danger)">CVSS {cwe.cvss}</Tag>
              <Tag>{cwe.tool} · {cwe.rule}</Tag>
            </div>
          </div>
          <SeverityPill severity={cwe.severity} />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 16 }}>
          {[
            { label: "What", body: cwe.what },
            { label: "Why", body: cwe.why },
            { label: "How", body: cwe.how },
          ].map(s => (
            <div key={s.label} style={{ borderTop: "2px solid var(--accent)", paddingTop: 10 }}>
              <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--accent)", textTransform: "uppercase", letterSpacing: 1.4, marginBottom: 6 }}>{s.label}</div>
              <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--textDim)" }}>{s.body}</div>
            </div>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>vulnerable · line 19</div>
            <CodeBlock code={cwe.vulnCode} lang="python" highlightLines={[6]} />
          </div>
          <div>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--ok)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>patched · gemini-2.5-pro · iteration 1</div>
            <CodeBlock code={cwe.patchedCode} lang="python" highlightLines={[6, 7]} />
          </div>
        </div>
      </Panel>

      {/* CoT reasoning */}
      <Panel title="fixer · chain-of-thought">
        <ol style={{ paddingLeft: 20, margin: 0, color: "var(--textDim)", fontSize: 13.5, lineHeight: 1.7 }}>
          <li><b style={{ color: "var(--text)" }}>Trace the taint flow.</b> stdin → username → f-string → execute. The user value reaches the SQL parser as part of the query string itself.</li>
          <li><b style={{ color: "var(--text)" }}>Pick a mitigation.</b> Bind parameters keep the query plane static. Validation alone is fragile — every new payload is a new bypass.</li>
          <li><b style={{ color: "var(--text)" }}>Rewrite get_user.</b> Replace the f-string with a `?` placeholder and pass the username as a tuple to `execute`.</li>
          <li><b style={{ color: "var(--text)" }}>Verify semantics.</b> Schema unchanged, return shape unchanged, `len(rows)` for legitimate user still 1. Marker only fires if rows &gt; 1.</li>
        </ol>
      </Panel>

      {/* Red-team verification */}
      <Panel title="red-team · sandbox replay">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>against vulnerable build</div>
            <SandboxOutput exploit={cwe.exploit} stdout={`Matched 3 row(s):\n(1, 'alice', 'admin')\n(2, 'bob', 'user')\n(3, 'carol', 'user')\nGUARDIANLOOP_EXPLOIT_SUCCESS`} success={true} />
          </div>
          <div>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--ok)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>against patched build</div>
            <SandboxOutput exploit={cwe.exploit} stdout={`Matched 0 row(s):`} success={false} />
          </div>
        </div>
      </Panel>
    </div>
  );
};

const SandboxOutput = ({ exploit, stdout, success }) => (
  <div style={{ background: "var(--panelAlt)", border: "1px solid var(--border)", borderRadius: 5, fontFamily: "var(--fontMono)", fontSize: 12 }}>
    <div style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", color: "var(--textMute)", fontSize: 10, letterSpacing: 0.6 }}>
      $ docker run --network=none --read-only --tmpfs /tmp --memory=512m
    </div>
    <div style={{ padding: 12 }}>
      <div style={{ color: "var(--accent2)" }}>stdin → {exploit}</div>
      <div style={{ color: "var(--textDim)", marginTop: 8, whiteSpace: "pre-wrap" }}>{stdout}</div>
      <div style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 6, color: success ? "var(--danger)" : "var(--ok)" }}>
        <Icon name={success ? "x" : "check"} size={12} />
        <span>{success ? "exploit reproduced" : "exploit blocked · patch holds"}</span>
      </div>
    </div>
  </div>
);

// ========== NEW SCAN ==========
const NewScanScreen = ({ onStart }) => {
  const [mode, setMode] = uS1("upload");
  const [code, setCode] = uS1("");
  const [pr, setPr] = uS1("");
  const [drag, setDrag] = uS1(false);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 880 }}>
      <div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 4px" }}>New scan</h1>
        <div style={{ color: "var(--textDim)" }}>Run the full pipeline: Scout → Classifier → Fixer → Red-Team → Report.</div>
      </div>

      <div style={{ display: "flex", gap: 6 }}>
        {[
          { id: "upload", label: "Upload file", icon: "upload" },
          { id: "paste",  label: "Paste code", icon: "code" },
          { id: "pr",     label: "GitHub PR URL", icon: "git" },
        ].map(m => (
          <Btn key={m.id} primary={mode === m.id} icon={m.icon} onClick={() => setMode(m.id)}>{m.label}</Btn>
        ))}
      </div>

      <Panel padding={20}>
        {mode === "upload" && (
          <div onDragOver={e => { e.preventDefault(); setDrag(true); }}
               onDragLeave={() => setDrag(false)}
               onDrop={e => { e.preventDefault(); setDrag(false); }}
               style={{
                 border: `1.5px dashed ${drag ? "var(--accent)" : "var(--borderStrong)"}`,
                 borderRadius: 6, padding: "48px 24px", textAlign: "center",
                 background: drag ? "color-mix(in oklab, var(--accent) 6%, transparent)" : "var(--panelAlt)",
                 transition: "all 120ms",
               }}>
            <Icon name="upload" size={32} />
            <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 18, fontWeight: 600, marginTop: 12 }}>Drop a .py or .cpp file here</div>
            <div style={{ color: "var(--textDim)", fontSize: 13, marginTop: 4 }}>or click to browse · max 1 MB</div>
            <Btn primary icon="play" onClick={onStart} style={{ marginTop: 18 }}>Use demo · samples/demo_cwe89.py</Btn>
          </div>
        )}
        {mode === "paste" && (
          <div>
            <textarea value={code} onChange={e => setCode(e.target.value)}
              placeholder="# paste python or c++ source…"
              style={{
                width: "100%", height: 280, padding: 14,
                fontFamily: "var(--fontMono)", fontSize: 13, lineHeight: 1.7,
                background: "var(--panelAlt)", border: "1px solid var(--border)", color: "var(--text)",
                borderRadius: 5, outline: "none", resize: "vertical",
              }} />
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10 }}>
              <div style={{ display: "flex", gap: 6 }}>
                <Btn ghost onClick={() => setCode(VULN_PY)}>load CWE-89 sample</Btn>
                <Btn ghost onClick={() => setCode(VULN_CPP)}>load CWE-121 sample</Btn>
              </div>
              <Btn primary icon="play" onClick={onStart}>Scan now</Btn>
            </div>
          </div>
        )}
        {mode === "pr" && (
          <div>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", marginBottom: 6 }}>github pull request url</div>
            <input value={pr} onChange={e => setPr(e.target.value)}
              placeholder="https://github.com/org/repo/pull/1234"
              style={{
                width: "100%", padding: "12px 14px",
                fontFamily: "var(--fontMono)", fontSize: 13,
                background: "var(--panelAlt)", border: "1px solid var(--border)", color: "var(--text)",
                borderRadius: 5, outline: "none",
              }} />
            <div style={{ marginTop: 10, padding: 12, background: "var(--panelAlt)", border: "1px solid var(--border)", borderRadius: 5, fontSize: 12.5, color: "var(--textDim)" }}>
              <Icon name="shield" size={12} /> &nbsp;HMAC-validated webhook ingress · scans the PR diff only · posts a check-run comment with the report.
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
              <Btn primary icon="play" onClick={onStart}>Scan PR</Btn>
            </div>
          </div>
        )}
      </Panel>

      <Panel title="sandbox config · read-only preview">
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)", lineHeight: 1.8 }}>
          <div>--network=none &nbsp;--read-only &nbsp;--tmpfs /tmp &nbsp;--memory=512m &nbsp;--cpus=1</div>
          <div>image · python: <span style={{ color: "var(--text)" }}>guardianloop/python-sandbox:latest</span></div>
          <div>image · cpp:    <span style={{ color: "var(--text)" }}>guardianloop/cpp-sandbox:latest</span></div>
          <div>timeout: 30s &nbsp;· max-loop: 3 &nbsp;· fixer: gemini-2.5-pro &nbsp;· classifier: gemini-2.5-flash</div>
        </div>
      </Panel>
    </div>
  );
};

// ========== AGENTS VIEW ==========
const AgentsScreen = () => {
  const stats = {
    scout:      { runs: 47, avgMs: 890, lastRun: "12 min ago", model: "semgrep 1.62 + bandit 1.7.5" },
    classifier: { runs: 47, avgMs: 1240, lastRun: "12 min ago", model: "gemini-2.5-flash · NVD API" },
    fixer:      { runs: 47, avgMs: 2980, lastRun: "12 min ago", model: "gemini-2.5-pro · CoT k=4" },
    redteam:    { runs: 47, avgMs: 1180, lastRun: "12 min ago", model: "docker · ASan / sqlite3" },
    report:     { runs: 47, avgMs: 110,  lastRun: "12 min ago", model: "json + markdown writers" },
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 4px" }}>Agents</h1>
        <div style={{ color: "var(--textDim)" }}>Five LangGraph nodes, one shared Pydantic state. All idle, all green.</div>
      </div>

      {AGENTS.map(a => {
        const s = stats[a.id];
        return (
          <Panel key={a.id}>
            <div style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 16, alignItems: "center" }}>
              <div style={{
                width: 56, height: 56, borderRadius: 8, background: "var(--panelAlt)",
                border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center",
                color: "var(--accent)",
              }}>
                <Icon name={a.icon} size={22} />
              </div>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontFamily: "var(--fontDisplay)", fontSize: 17, fontWeight: 600 }}>{a.label}</span>
                  <Tag color="var(--ok)">● ready</Tag>
                </div>
                <div style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)", marginTop: 4 }}>{s.model}</div>
              </div>
              <div style={{ display: "flex", gap: 24, fontFamily: "var(--fontMono)", fontSize: 12 }}>
                <Stat2 label="runs"      value={s.runs} />
                <Stat2 label="avg dur"   value={`${(s.avgMs / 1000).toFixed(2)}s`} />
                <Stat2 label="last"      value={s.lastRun} />
              </div>
            </div>
          </Panel>
        );
      })}
    </div>
  );
};

const Stat2 = ({ label, value }) => (
  <div style={{ textAlign: "right" }}>
    <div style={{ color: "var(--textMute)", fontSize: 10, textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
    <div style={{ color: "var(--text)", fontSize: 14, marginTop: 2 }}>{value}</div>
  </div>
);

// ========== SETTINGS ==========
const SettingsScreen = () => {
  const [config, setConfig] = uS1({
    fixer_model: "gemini-2.5-pro",
    classifier_model: "gemini-2.5-flash",
    max_loop_iterations: 3,
    sandbox_timeout_seconds: 30,
    nvd_api_key: "••••••••••••••3a7f",
    google_api_key: "••••••••••••••e92c",
  });
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 920 }}>
      <div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 4px" }}>Settings</h1>
        <div style={{ color: "var(--textDim)" }}>Mirrors <span style={{ fontFamily: "var(--fontMono)", color: "var(--accent)" }}>config.yaml</span> + <span style={{ fontFamily: "var(--fontMono)", color: "var(--accent)" }}>.env</span>. Changes regenerate the files on save.</div>
      </div>

      <Panel title="models">
        <SettingRow label="fixer_model" desc="Chain-of-thought patch generation. Gemini 2.5 Pro recommended.">
          <Select value={config.fixer_model} onChange={v => setConfig({ ...config, fixer_model: v })}
            options={["gemini-2.5-pro", "gemini-2.5-flash", "claude-sonnet-4.5", "gpt-5"]} />
        </SettingRow>
        <SettingRow label="classifier_model" desc="NVD-augmented severity scoring. Flash is fine.">
          <Select value={config.classifier_model} onChange={v => setConfig({ ...config, classifier_model: v })}
            options={["gemini-2.5-flash", "gemini-2.5-pro"]} />
        </SettingRow>
      </Panel>

      <Panel title="pipeline">
        <SettingRow label="max_loop_iterations" desc="Red-Team → Fixer retries before giving up.">
          <Numeric value={config.max_loop_iterations} onChange={v => setConfig({ ...config, max_loop_iterations: v })} min={1} max={10} />
        </SettingRow>
        <SettingRow label="sandbox_timeout_seconds" desc="Per-exploit Docker run wallclock cap.">
          <Numeric value={config.sandbox_timeout_seconds} onChange={v => setConfig({ ...config, sandbox_timeout_seconds: v })} min={5} max={300} />
        </SettingRow>
      </Panel>

      <Panel title="sandbox flags · non-negotiable">
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 12.5, lineHeight: 2, color: "var(--textDim)" }}>
          <div>--network=none</div>
          <div>--read-only</div>
          <div>--tmpfs /tmp</div>
          <div>--memory=512m</div>
          <div>--cpus=1</div>
        </div>
        <div style={{ marginTop: 10, fontSize: 12, color: "var(--textMute)" }}>
          <Icon name="shield" size={11} /> &nbsp;Locked. Loosening these requires a security review &amp; code change.
        </div>
      </Panel>

      <Panel title="secrets · .env">
        <SettingRow label="GOOGLE_API_KEY" desc="Used by Fixer + Classifier."><MaskedInput value={config.google_api_key} /></SettingRow>
        <SettingRow label="NVD_API_KEY" desc="Raises rate limit 5 → 50 / 30s."><MaskedInput value={config.nvd_api_key} /></SettingRow>
      </Panel>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Btn ghost>Discard</Btn>
        <Btn primary icon="check">Save changes</Btn>
      </div>
    </div>
  );
};

const SettingRow = ({ label, desc, children }) => (
  <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 16, alignItems: "center", padding: "12px 0", borderBottom: "1px solid var(--border)" }}>
    <div>
      <div style={{ fontFamily: "var(--fontMono)", fontSize: 13, color: "var(--text)" }}>{label}</div>
      <div style={{ fontSize: 12, color: "var(--textDim)", marginTop: 2 }}>{desc}</div>
    </div>
    {children}
  </div>
);

const Select = ({ value, onChange, options }) => (
  <select value={value} onChange={e => onChange(e.target.value)} style={{
    padding: "7px 10px", background: "var(--panelAlt)", border: "1px solid var(--border)",
    color: "var(--text)", fontFamily: "var(--fontMono)", fontSize: 12, borderRadius: 4, minWidth: 200,
  }}>
    {options.map(o => <option key={o} value={o}>{o}</option>)}
  </select>
);

const Numeric = ({ value, onChange, min, max }) => (
  <input type="number" value={value} min={min} max={max}
    onChange={e => onChange(parseInt(e.target.value, 10))} style={{
    padding: "7px 10px", background: "var(--panelAlt)", border: "1px solid var(--border)",
    color: "var(--text)", fontFamily: "var(--fontMono)", fontSize: 12, borderRadius: 4, width: 100,
  }} />
);

const MaskedInput = ({ value }) => (
  <input value={value} readOnly style={{
    padding: "7px 10px", background: "var(--panelAlt)", border: "1px solid var(--border)",
    color: "var(--textDim)", fontFamily: "var(--fontMono)", fontSize: 12, borderRadius: 4, width: 240,
  }} />
);

Object.assign(window, { OverviewScreen, FindingsScreen, ScanDetailScreen, NewScanScreen, AgentsScreen, SettingsScreen });
