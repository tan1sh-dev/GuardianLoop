// Live Scan screen — idle state when no runId, real polling when runId is set
const { useState, useEffect, useRef } = React;

const AGENTS = [
  { id: "scout",      label: "Scout",      sub: "semgrep · auto + custom", icon: "search" },
  { id: "classifier", label: "Classifier", sub: "NVD CVE/CVSS",            icon: "layers" },
  { id: "fixer",      label: "Fixer",      sub: "gemini-2.5-pro · CoT",    icon: "spark" },
  { id: "redteam",    label: "Red-Team",   sub: "docker sandbox",           icon: "bug" },
  { id: "report",     label: "Report",     sub: "json + markdown",          icon: "flag" },
];

// ---------- pipeline horizontal viz ----------
const PipelineViz = ({ activeIdx, completedIdx, loopActive, speed = 1 }) => (
  <div style={{ position: "relative", padding: "24px 8px 8px" }}>
    {loopActive && (
      <svg style={{ position: "absolute", left: 0, right: 0, top: -6, height: 38, width: "100%", overflow: "visible" }}
           viewBox="0 0 1000 40" preserveAspectRatio="none">
        <path d="M 770 20 C 770 -20, 430 -20, 430 20"
              fill="none" stroke="var(--accent)" strokeWidth="1.4"
              strokeDasharray="4 4" opacity="0.7" />
        <polygon points="430,20 438,16 438,24" fill="var(--accent)" />
        <text x="600" y="-2" textAnchor="middle"
              fontFamily="var(--fontMono)" fontSize="10" fill="var(--accent)">
          loop · iteration 2 of 3
        </text>
      </svg>
    )}
    <div style={{ display: "grid", gridTemplateColumns: `repeat(${AGENTS.length}, 1fr)`, gap: 0, position: "relative" }}>
      {AGENTS.map((a, i) => {
        const isActive  = i === activeIdx;
        const isDone    = completedIdx > i;
        return (
          <React.Fragment key={a.id}>
            <AgentNode agent={a} active={isActive} done={isDone} pending={!isActive && !isDone} speed={speed} />
            {i < AGENTS.length - 1 && <PipelineConnector active={isDone} />}
          </React.Fragment>
        );
      })}
    </div>
  </div>
);

const AgentNode = ({ agent, active, done, pending, speed }) => {
  const color = done ? "var(--ok)" : active ? "var(--accent)" : "var(--textMute)";
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, gridColumn: "span 1", position: "relative" }}>
      <div style={{
        width: 64, height: 64, borderRadius: 10,
        border: `1.5px solid ${color}`,
        background: active ? `color-mix(in oklab, var(--accent) 14%, var(--panel))`
                  : done   ? `color-mix(in oklab, var(--ok) 8%, var(--panel))`
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
            background: "var(--ok)", color: "var(--bg)", display: "flex", alignItems: "center", justifyContent: "center",
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
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--accent)", textTransform: "uppercase", letterSpacing: 1, animation: "gl-blink 1s infinite" }}>● working</div>
      )}
    </div>
  );
};

const PipelineConnector = ({ active }) => (
  <div style={{ position: "absolute", height: 2, top: 56, left: 0, right: 0, pointerEvents: "none" }}>
    <svg width="100%" height="2" style={{ position: "absolute", left: 0, top: 0 }}>
      <line x1="0" y1="1" x2="100%" y2="1" stroke={active ? "var(--accent)" : "var(--border)"} strokeWidth="1" />
    </svg>
  </div>
);

// ---------- log stream ----------
const LogStream = ({ logs, currentMs }) => {
  const ref = useRef(null);
  const visible = logs.filter(l => (l.ms ?? 0) <= currentMs);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [visible.length]);

  const colorFor = (level) =>
    level === "ok"    ? "var(--ok)" :
    level === "warn"  ? "var(--warn)" :
    level === "error" ? "var(--danger)" :
    level === "debug" ? "var(--textMute)" : "var(--textDim)";

  return (
    <div ref={ref} style={{ fontFamily: "var(--fontMono)", fontSize: 12, lineHeight: 1.7, height: 280, overflowY: "auto", padding: "8px 4px" }}>
      {visible.map((l, i) => (
        <div key={i} style={{ display: "flex", gap: 10, padding: "1px 8px", whiteSpace: "nowrap" }}>
          <span style={{ color: "var(--textMute)", minWidth: 60 }}>{((l.ms ?? 0) / 1000).toFixed(2)}s</span>
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

// ---------- idle state ----------
const IdleScreen = ({ onNav }) => (
  <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
    {/* header */}
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
      <div>
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", letterSpacing: 1.4, textTransform: "uppercase" }}>
          ○ Idle · no active scan
        </div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "8px 0 4px", letterSpacing: -0.5 }}>
          Live scan
        </h1>
        <div style={{ color: "var(--textDim)", fontSize: 13 }}>
          Ready when you are. Submit a target to start the pipeline.
        </div>
      </div>
      <Btn primary icon="play" onClick={() => onNav("new")}>New scan</Btn>
    </div>

    {/* static grey pipeline */}
    <Panel title="pipeline · langgraph" padding={0}>
      <PipelineViz activeIdx={-1} completedIdx={0} loopActive={false} />
    </Panel>

    {/* CTA + status */}
    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
      {/* left — awaiting */}
      <Panel>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", padding: "28px 16px", gap: 18 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 12,
            background: "var(--panelAlt)", border: "1px solid var(--border)",
            display: "flex", alignItems: "center", justifyContent: "center",
            color: "var(--textMute)",
          }}>
            <Icon name="pulse" size={24} />
          </div>
          <div>
            <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 20, fontWeight: 600, color: "var(--text)", marginBottom: 6 }}>
              No scan running
            </div>
            <div style={{ fontSize: 13, color: "var(--textDim)", lineHeight: 1.6, maxWidth: 380 }}>
              Upload a file, paste code, or point to a GitHub PR to kick off
              Scout → Classifier → Fixer → Red-Team → Report.
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "center" }}>
            <Btn primary icon="play"   onClick={() => onNav("new")}>Upload a file</Btn>
            <Btn icon="code"  onClick={() => onNav("new")}>Paste code</Btn>
            <Btn icon="git"   onClick={() => onNav("new")}>GitHub PR</Btn>
          </div>
        </div>
      </Panel>

      {/* right — system status */}
      <Panel title="system status">
        <div style={{ display: "flex", flexDirection: "column", gap: 14, padding: "4px 0" }}>
          {[
            { label: "semgrep",  value: "ready · 1.163.0 · WSL",    ok: true  },
            { label: "docker",   value: "2 containers idle",          ok: true  },
            { label: "nvd api",  value: "47 / 50 budget",            ok: true  },
            { label: "fixer",    value: "gemini-2.5-pro",            ok: true  },
            { label: "sandbox",  value: "--network=none · read-only", ok: true  },
          ].map(row => (
            <div key={row.label} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8 }}>
              <div style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)" }}>{row.label}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", textAlign: "right" }}>
                <span style={{ color: row.ok ? "var(--ok)" : "var(--danger)", fontSize: 8 }}>●</span>
                {row.value}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  </div>
);

// ---------- active scan screen ----------
const ActiveScanScreen = ({ tweaks, runId, onNav, onComplete }) => {
  const speed = tweaks.animSpeed || 1;

  const [realLogs, setRealLogs]         = useState([]);
  const [activeAgentIdx, setActive]     = useState(0);
  const [isComplete, setIsComplete]     = useState(false);
  const [runSummary, setRunSummary]     = useState(null);
  const [sourceName, setSourceName]     = useState("");

  useEffect(() => {
    let cancelled = false;
    let done = false;

    const poll = async () => {
      try {
        const r = await fetch(`/api/runs/${runId}/logs`);
        if (!r.ok || cancelled) return;
        const data = await r.json();
        setRealLogs(data.logs || []);
        setActive(data.active_agent_idx ?? 0);
        if (data.is_complete && !done) {
          done = true;
          setIsComplete(true);
          const r2 = await fetch(`/api/runs/${runId}`);
          if (r2.ok && !cancelled) {
            const full = await r2.json();
            setRunSummary(full);
            setSourceName(full.summary?.source_file || "");
          }
        }
      } catch (_) {}
    };

    poll();
    const id = setInterval(() => { if (!done) poll(); }, 2000);
    return () => { cancelled = true; clearInterval(id); };
  }, [runId]);

  const isDone        = isComplete;
  const vizActiveIdx  = isDone ? -1 : activeAgentIdx;
  const vizDoneCount  = isDone ? AGENTS.length : activeAgentIdx;
  const currentMs     = realLogs.length ? realLogs[realLogs.length - 1].ms + 9999 : 0;
  const displaySource = sourceName ? sourceName.split(/[\\/]/).pop() : runId;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--accent)", letterSpacing: 1.4, textTransform: "uppercase" }}>
            {isDone ? "● Complete" : "● Live"} · run {runId}
          </div>
          <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "8px 0 4px", letterSpacing: -0.5 }}>
            {isDone ? "Scan complete —" : "Scanning"}{" "}
            <span style={{ color: "var(--accent)" }}>{displaySource}</span>
          </h1>
          <div style={{ color: "var(--textDim)", fontSize: 13 }}>
            {isDone
              ? `${runSummary?.summary?.totals?.findings ?? 0} findings · ${runSummary?.summary?.totals?.patches ?? 0} patches`
              : `${AGENTS[activeAgentIdx]?.label || "pipeline"} running…`}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {isDone && <Btn primary icon="arrow" onClick={() => onComplete(runSummary)}>Open report</Btn>}
        </div>
      </div>

      {/* pipeline viz */}
      <Panel title="pipeline · langgraph" padding={0}>
        <PipelineViz activeIdx={vizActiveIdx} completedIdx={vizDoneCount} loopActive={false} speed={speed} />
      </Panel>

      {/* logs + snapshot */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
        <Panel title="streaming logs · structlog">
          <LogStream logs={realLogs} currentMs={currentMs} />
        </Panel>
        <Panel title="snapshot">
          <div style={{ display: "grid", gap: 14 }}>
            <Stat label="run id"   value={runId.slice(-8)} />
            <Stat label="status"   value={isDone ? "complete ✓" : (AGENTS[activeAgentIdx]?.label || "…")}
                                    valueColor={isDone ? "var(--ok)" : "var(--accent)"} />
            <Stat label="findings" value={runSummary?.summary?.totals?.findings ?? "—"} />
            <Stat label="patches"  value={runSummary?.summary?.totals?.patches ?? "—"} />
          </div>
        </Panel>
      </div>
    </div>
  );
};

// ---------- live scan screen (router) ----------
const LiveScanScreen = ({ tweaks, runId, onNav, onComplete }) => {
  if (!runId) return <IdleScreen onNav={onNav} />;
  return <ActiveScanScreen tweaks={tweaks} runId={runId} onNav={onNav} onComplete={onComplete} />;
};

const Stat = ({ label, value, sub, valueColor = "var(--text)" }) => (
  <div>
    <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
    <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 22, fontWeight: 600, color: valueColor, marginTop: 2 }}>{value}</div>
    {sub && <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textDim)", marginTop: 2 }}>{sub}</div>}
  </div>
);

Object.assign(window, { LiveScanScreen, AGENTS, PipelineViz });
