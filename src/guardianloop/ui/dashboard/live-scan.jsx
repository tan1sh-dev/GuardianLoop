// Live Scan + Agents view — the hero screen
const { useState, useEffect, useRef } = React;

const AGENTS = [
  { id: "scout",      label: "Scout",      sub: "semgrep + bandit",     icon: "search" },
  { id: "classifier", label: "Classifier", sub: "NVD CVE/CVSS",         icon: "layers" },
  { id: "fixer",      label: "Fixer",      sub: "gemini-2.5-pro · CoT", icon: "spark" },
  { id: "redteam",    label: "Red-Team",   sub: "docker sandbox",       icon: "bug" },
  { id: "report",     label: "Report",     sub: "json + markdown",      icon: "flag" },
];

// ---------- pipeline horizontal viz ----------
const PipelineViz = ({ activeIdx, completedIdx, loopActive, speed = 1 }) => {
  return (
    <div style={{ position: "relative", padding: "24px 8px 8px" }}>
      {/* loop-back arrow */}
      {loopActive && (
        <svg style={{ position: "absolute", left: 0, right: 0, top: -6, height: 38, width: "100%", overflow: "visible" }}
             viewBox="0 0 1000 40" preserveAspectRatio="none">
          <path d={`M 770 20 C 770 -20, 430 -20, 430 20`}
                fill="none" stroke="var(--accent)" strokeWidth="1.4"
                strokeDasharray="4 4" opacity="0.7" />
          <polygon points="430,20 438,16 438,24" fill="var(--accent)" />
          <text x="600" y="-2" textAnchor="middle"
                fontFamily="var(--fontMono)" fontSize="10" fill="var(--accent)">
            loop · iteration 2 of 3
          </text>
        </svg>
      )}
      <div style={{
        display: "grid", gridTemplateColumns: `repeat(${AGENTS.length}, 1fr)`,
        gap: 0, position: "relative",
      }}>
        {AGENTS.map((a, i) => {
          const isActive = i === activeIdx;
          const isDone = i < completedIdx || (i === completedIdx && activeIdx > i);
          const isPending = i > activeIdx;
          return (
            <React.Fragment key={a.id}>
              <AgentNode agent={a} active={isActive} done={isDone} pending={isPending} speed={speed} />
              {i < AGENTS.length - 1 && (
                <PipelineConnector active={isActive || isDone} flowing={i === activeIdx - 1 || (i === activeIdx && isActive)} speed={speed} />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};

const AgentNode = ({ agent, active, done, pending, speed }) => {
  const color = done ? "var(--ok)" : active ? "var(--accent)" : "var(--textMute)";
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", gap: 8,
      gridColumn: `span 1`,
      position: "relative",
    }}>
      <div style={{
        width: 64, height: 64, borderRadius: 10,
        border: `1.5px solid ${color}`,
        background: active ? `color-mix(in oklab, var(--accent) 14%, var(--panel))`
                  : done ? `color-mix(in oklab, var(--ok) 8%, var(--panel))`
                  : "var(--panel)",
        display: "flex", alignItems: "center", justifyContent: "center",
        position: "relative", color,
        boxShadow: active ? `0 0 32px color-mix(in oklab, var(--accent) 50%, transparent)` : "none",
        transition: "all 200ms",
      }}>
        <Icon name={agent.icon} size={24} />
        {active && (
          <div style={{
            position: "absolute", inset: -3, borderRadius: 12,
            border: "1px solid var(--accent)", opacity: 0.5,
            animation: `gl-ring ${1.4 / speed}s infinite`,
          }} />
        )}
        {done && (
          <div style={{
            position: "absolute", top: -6, right: -6, width: 18, height: 18, borderRadius: "50%",
            background: "var(--ok)", color: "var(--bg)", display: "flex",
            alignItems: "center", justifyContent: "center",
          }}>
            <Icon name="check" size={11} />
          </div>
        )}
      </div>
      <div style={{ textAlign: "center" }}>
        <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 13, fontWeight: 600, color: "var(--text)" }}>{agent.label}</div>
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", marginTop: 2 }}>{agent.sub}</div>
      </div>
      {active && (
        <div style={{
          fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--accent)",
          textTransform: "uppercase", letterSpacing: 1,
          animation: "gl-blink 1s infinite",
        }}>● working</div>
      )}
    </div>
  );
};

const PipelineConnector = ({ active, flowing, speed }) => (
  <div style={{
    position: "absolute", height: 2, top: 56, left: 0, right: 0, pointerEvents: "none",
  }}>
    <svg width="100%" height="2" style={{ position: "absolute", left: 0, top: 0 }}>
      <line x1="0" y1="1" x2="100%" y2="1"
            stroke={active ? "var(--accent)" : "var(--border)"} strokeWidth="1" />
    </svg>
  </div>
);

// ---------- log stream ----------
const LogStream = ({ logs, currentMs }) => {
  const ref = useRef(null);
  const visible = logs.filter(l => l.ms <= currentMs);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [visible.length]);

  const colorFor = (level) =>
    level === "ok" ? "var(--ok)" :
    level === "warn" ? "var(--warn)" :
    level === "error" ? "var(--danger)" :
    level === "debug" ? "var(--textMute)" : "var(--textDim)";

  return (
    <div ref={ref} style={{
      fontFamily: "var(--fontMono)", fontSize: 12, lineHeight: 1.7,
      height: 280, overflowY: "auto", padding: "8px 4px",
    }}>
      {visible.map((l, i) => (
        <div key={i} style={{ display: "flex", gap: 10, padding: "1px 8px", whiteSpace: "nowrap" }}>
          <span style={{ color: "var(--textMute)", minWidth: 60 }}>{(l.ms / 1000).toFixed(2)}s</span>
          <span style={{ color: "var(--accent2)", minWidth: 80 }}>[{l.agent}]</span>
          <span style={{ color: colorFor(l.level), minWidth: 50, textTransform: "uppercase", fontSize: 10 }}>{l.level}</span>
          <span style={{ color: "var(--text)", whiteSpace: "pre-wrap", overflow: "hidden", textOverflow: "ellipsis" }}>{l.msg}</span>
        </div>
      ))}
      {visible.length === 0 && (
        <div style={{ color: "var(--textMute)", padding: "8px 12px" }}>$ awaiting pipeline start_</div>
      )}
      <span style={{ color: "var(--accent)", padding: "0 8px", animation: "gl-blink 1s infinite" }}>▌</span>
    </div>
  );
};

// ---------- live scan screen ----------
const LiveScanScreen = ({ tweaks, onComplete }) => {
  const [running, setRunning] = useState(true);
  const [t, setT] = useState(0); // ms
  const speed = tweaks.animSpeed || 1;
  const total = 7000;

  useEffect(() => {
    if (!running) return;
    const start = Date.now();
    const id = setInterval(() => {
      const elapsed = (Date.now() - start) * speed;
      setT(prev => {
        if (prev >= total) {
          clearInterval(id);
          return total;
        }
        return Math.min(elapsed, total);
      });
    }, 40);
    return () => clearInterval(id);
  }, [running, speed]);

  // map time → active agent
  const phases = [
    { agent: 0, end: 1100 }, // scout
    { agent: 1, end: 2400 }, // classifier
    { agent: 2, end: 5300 }, // fixer
    { agent: 3, end: 6500 }, // redteam
    { agent: 4, end: 7000 }, // report
  ];
  const activeIdx = phases.findIndex(p => t < p.end);
  const completedIdx = activeIdx === -1 ? AGENTS.length : activeIdx;
  const isDone = t >= total;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--accent)", letterSpacing: 1.4, textTransform: "uppercase" }}>
            ● Live · run 20260426T130824Z
          </div>
          <h1 style={{
            fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "8px 0 4px",
            letterSpacing: -0.5,
          }}>
            Scanning <span style={{ color: "var(--accent)" }}>samples/demo_cwe89.py</span>
          </h1>
          <div style={{ color: "var(--textDim)", fontSize: 13 }}>
            python · 50 LOC · started {(t / 1000).toFixed(1)}s ago
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn icon="refresh" onClick={() => { setT(0); setRunning(true); }}>Restart</Btn>
          {isDone && <Btn primary icon="arrow" onClick={onComplete}>Open report</Btn>}
        </div>
      </div>

      {/* pipeline */}
      <Panel title="pipeline · langgraph" padding={0}>
        <PipelineViz activeIdx={isDone ? -1 : activeIdx} completedIdx={completedIdx}
                     loopActive={tweaks.showLoopback && t > 4000 && t < 5300} speed={speed} />
      </Panel>

      {/* progress + stats */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
        <Panel title="streaming logs · structlog">
          <LogStream logs={SCAN_LOGS} currentMs={t} />
        </Panel>
        <Panel title="snapshot">
          <div style={{ display: "grid", gap: 14 }}>
            <Stat label="elapsed" value={`${(t / 1000).toFixed(2)}s`} />
            <Stat label="findings" value={t > 800 ? "1" : "—"} sub={t > 2200 ? "CWE-89 · CVSS 9.8" : ""} />
            <Stat label="patches" value={t > 5200 ? "1" : "—"} sub={t > 5200 ? "v1 · 24 tokens" : ""} />
            <Stat label="exploit holds" value={t > 6400 ? "yes ✓" : "—"}
                  valueColor={t > 6400 ? "var(--ok)" : "var(--text)"} />
            <Stat label="loop" value={`${tweaks.showLoopback ? 2 : 1} / 3`}
                  sub={tweaks.showLoopback ? "fixer re-attempt" : "single pass"} />
          </div>
        </Panel>
      </div>
    </div>
  );
};

const Stat = ({ label, value, sub, valueColor = "var(--text)" }) => (
  <div>
    <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
    <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 22, fontWeight: 600, color: valueColor, marginTop: 2 }}>{value}</div>
    {sub && <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textDim)", marginTop: 2 }}>{sub}</div>}
  </div>
);

Object.assign(window, { LiveScanScreen, AGENTS, PipelineViz });
