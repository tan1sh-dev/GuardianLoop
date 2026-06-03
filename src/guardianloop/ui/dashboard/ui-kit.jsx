// Shared UI primitives + theme system

const THEMES = {
  console: {
    name: "Console",
    bg: "#0a0b0e",
    panel: "#101218",
    panelAlt: "#13161e",
    border: "#1f2330",
    borderStrong: "#2a3040",
    text: "#e8eaef",
    textDim: "#8b92a5",
    textMute: "#5a6075",
    accent: "#a78bfa",      // violet
    accentDim: "#7c3aed",
    accent2: "#67e8f9",     // cyan secondary
    danger: "#f87171",
    warn: "#fbbf24",
    ok: "#86efac",
    info: "#93c5fd",
    fontUI: '"Inter", system-ui, sans-serif',
    fontMono: '"JetBrains Mono", "SF Mono", ui-monospace, monospace',
    fontDisplay: '"Inter", system-ui, sans-serif',
  },
  editorial: {
    name: "Editorial",
    bg: "#f7f5ef",
    panel: "#ffffff",
    panelAlt: "#fbf9f3",
    border: "#e6e2d6",
    borderStrong: "#cdc7b6",
    text: "#1a1814",
    textDim: "#5b574c",
    textMute: "#8a8576",
    accent: "#5b21b6",
    accentDim: "#7c3aed",
    accent2: "#0891b2",
    danger: "#b91c1c",
    warn: "#a16207",
    ok: "#15803d",
    info: "#1d4ed8",
    fontUI: '"Inter", system-ui, sans-serif',
    fontMono: '"JetBrains Mono", ui-monospace, monospace',
    fontDisplay: '"Fraunces", "Times New Roman", serif',
  },
  cyber: {
    name: "Cyber-grid",
    bg: "#06070b",
    panel: "#0c0e16",
    panelAlt: "#0f1220",
    border: "#1a1f35",
    borderStrong: "#2d3559",
    text: "#e8ecff",
    textDim: "#8a92b8",
    textMute: "#525a82",
    accent: "#34d399",
    accentDim: "#059669",
    accent2: "#38bdf8",
    danger: "#fb7185",
    warn: "#fcd34d",
    ok: "#4ade80",
    info: "#60a5fa",
    fontUI: '"Space Grotesk", "Inter", sans-serif',
    fontMono: '"JetBrains Mono", ui-monospace, monospace',
    fontDisplay: '"Space Grotesk", sans-serif',
  },
  amber: {
    name: "Amber CRT",
    bg: "#0c0904",
    panel: "#13100a",
    panelAlt: "#1a1610",
    border: "#2a2114",
    borderStrong: "#3d2f1d",
    text: "#fde68a",
    textDim: "#b08838",
    textMute: "#6b5224",
    accent: "#fbbf24",
    accentDim: "#d97706",
    accent2: "#fb923c",
    danger: "#ef4444",
    warn: "#f59e0b",
    ok: "#a3e635",
    info: "#fcd34d",
    fontUI: '"JetBrains Mono", ui-monospace, monospace',
    fontMono: '"JetBrains Mono", ui-monospace, monospace',
    fontDisplay: '"JetBrains Mono", ui-monospace, monospace',
  },
  paper: {
    name: "Paper",
    bg: "#fafaf7",
    panel: "#ffffff",
    panelAlt: "#f4f4ee",
    border: "#e4e4dc",
    borderStrong: "#c8c8be",
    text: "#0a0a0a",
    textDim: "#525252",
    textMute: "#878780",
    accent: "#171717",
    accentDim: "#404040",
    accent2: "#0a0a0a",
    danger: "#dc2626",
    warn: "#b45309",
    ok: "#15803d",
    info: "#1e40af",
    fontUI: '"Inter", system-ui, sans-serif',
    fontMono: '"JetBrains Mono", ui-monospace, monospace',
    fontDisplay: '"Inter", system-ui, sans-serif',
  },
  oceanic: {
    name: "Oceanic",
    bg: "#0a1628",
    panel: "#0f1f37",
    panelAlt: "#142a47",
    border: "#1f3a5f",
    borderStrong: "#2d527e",
    text: "#e0f2fe",
    textDim: "#7dd3fc",
    textMute: "#475569",
    accent: "#38bdf8",
    accentDim: "#0284c7",
    accent2: "#5eead4",
    danger: "#fb7185",
    warn: "#fbbf24",
    ok: "#4ade80",
    info: "#a5f3fc",
    fontUI: '"Inter", system-ui, sans-serif',
    fontMono: '"JetBrains Mono", ui-monospace, monospace',
    fontDisplay: '"Inter", system-ui, sans-serif',
  },
  rosewood: {
    name: "Rosewood",
    bg: "#1a0e10",
    panel: "#241418",
    panelAlt: "#2c181d",
    border: "#3d2229",
    borderStrong: "#5a2f3a",
    text: "#fce7f3",
    textDim: "#f9a8d4",
    textMute: "#9d6573",
    accent: "#fb7185",
    accentDim: "#e11d48",
    accent2: "#fda4af",
    danger: "#f43f5e",
    warn: "#fbbf24",
    ok: "#86efac",
    info: "#c4b5fd",
    fontUI: '"Inter", system-ui, sans-serif',
    fontMono: '"JetBrains Mono", ui-monospace, monospace',
    fontDisplay: '"Fraunces", serif',
  },
  matrix: {
    name: "Matrix",
    bg: "#000000",
    panel: "#040a06",
    panelAlt: "#06120a",
    border: "#0d2615",
    borderStrong: "#163a22",
    text: "#bbf7d0",
    textDim: "#4ade80",
    textMute: "#15803d",
    accent: "#22c55e",
    accentDim: "#16a34a",
    accent2: "#a7f3d0",
    danger: "#f87171",
    warn: "#fde047",
    ok: "#86efac",
    info: "#67e8f9",
    fontUI: '"JetBrains Mono", ui-monospace, monospace',
    fontMono: '"JetBrains Mono", ui-monospace, monospace',
    fontDisplay: '"JetBrains Mono", ui-monospace, monospace',
  },
};

function applyTheme(name) {
  const t = THEMES[name] || THEMES.console;
  const r = document.documentElement;
  Object.entries(t).forEach(([k, v]) => {
    if (typeof v === "string") r.style.setProperty(`--${k}`, v);
  });
  r.dataset.theme = name;
}

// ---------- shared SVG icons ----------
const Icon = ({ name, size = 16, ...rest }) => {
  const paths = {
    home:       <><path d="M3 11l9-8 9 8" /><path d="M5 10v10h14V10" /></>,
    play:       <polygon points="6,4 20,12 6,20" />,
    file:       <><path d="M14 3H6v18h12V7" /><path d="M14 3v4h4" /></>,
    list:       <><path d="M4 6h16M4 12h16M4 18h16" /></>,
    layers:     <><path d="M12 3l9 5-9 5-9-5 9-5z" /><path d="M3 13l9 5 9-5" /><path d="M3 18l9 5 9-5" /></>,
    book:       <><path d="M4 4h7a3 3 0 013 3v14a2 2 0 00-2-2H4z" /><path d="M20 4h-7a3 3 0 00-3 3v14a2 2 0 012-2h8z" /></>,
    cog:        <><circle cx="12" cy="12" r="3" /><path d="M12 1v4M12 19v4M4.2 4.2l2.8 2.8M17 17l2.8 2.8M1 12h4M19 12h4M4.2 19.8l2.8-2.8M17 7l2.8-2.8" /></>,
    search:     <><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></>,
    arrow:      <><path d="M5 12h14M13 5l7 7-7 7" /></>,
    check:      <path d="M4 12l5 5L20 6" />,
    x:          <><path d="M5 5l14 14M19 5L5 19" /></>,
    bug:        <><circle cx="12" cy="13" r="5" /><path d="M12 8V5M9 5h6M3 13h4M17 13h4M5 9l3 2M19 9l-3 2M5 17l3-1M19 17l-3-1" /></>,
    shield:     <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z" />,
    pulse:      <path d="M3 12h4l2-6 4 12 2-6h6" />,
    code:       <><path d="M8 6l-5 6 5 6" /><path d="M16 6l5 6-5 6" /><path d="M14 4l-4 16" /></>,
    upload:     <><path d="M12 16V4M6 10l6-6 6 6" /><path d="M4 18v2h16v-2" /></>,
    git:        <><circle cx="6" cy="6" r="2" /><circle cx="6" cy="18" r="2" /><circle cx="18" cy="12" r="2" /><path d="M6 8v8M6 12h8a4 4 0 004-4" /></>,
    spark:      <><path d="M12 2l2 6 6 2-6 2-2 6-2-6-6-2 6-2z" /></>,
    chevron:    <path d="M9 6l6 6-6 6" />,
    download:   <><path d="M12 4v12M6 14l6 6 6-6" /><path d="M4 22h16" /></>,
    refresh:    <><path d="M4 12a8 8 0 0114-5l2-2v6h-6" /><path d="M20 12a8 8 0 01-14 5l-2 2v-6h6" /></>,
    dot:        <circle cx="12" cy="12" r="4" />,
    flag:       <><path d="M5 21V4M5 4h12l-2 4 2 4H5" /></>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...rest}>
      {paths[name]}
    </svg>
  );
};

// ---------- pill / badge ----------
const SeverityPill = ({ severity }) => {
  const map = {
    CRITICAL: { c: "var(--danger)", l: "CRIT" },
    HIGH:     { c: "var(--warn)",   l: "HIGH" },
    MEDIUM:   { c: "var(--info)",   l: "MED"  },
    LOW:      { c: "var(--textDim)", l: "LOW" },
    INFO:     { c: "var(--textMute)", l: "INFO"},
  };
  const m = map[severity] || map.INFO;
  return (
    <span style={{
      fontFamily: "var(--fontMono)", fontSize: 10, fontWeight: 600, letterSpacing: 0.6,
      padding: "2px 6px", border: `1px solid ${m.c}`, color: m.c, borderRadius: 3,
      background: "color-mix(in oklab, var(--panel) 70%, transparent)",
    }}>{m.l}</span>
  );
};

const Tag = ({ children, color = "var(--textDim)", style = {} }) => (
  <span style={{
    fontFamily: "var(--fontMono)", fontSize: 11, color, padding: "2px 6px",
    background: "color-mix(in oklab, var(--panel) 50%, transparent)",
    border: "1px solid var(--border)", borderRadius: 3, ...style,
  }}>{children}</span>
);

const StatusDot = ({ status }) => {
  const c = status === "complete" ? "var(--ok)"
         : status === "failed"   ? "var(--danger)"
         : status === "running"  ? "var(--accent)"
         : "var(--textMute)";
  return (
    <span style={{
      display: "inline-block", width: 7, height: 7, borderRadius: "50%",
      background: c, boxShadow: status === "running" ? `0 0 8px ${c}` : "none",
      animation: status === "running" ? "gl-pulse 1.2s infinite" : "none",
    }} />
  );
};

const Sparkline = ({ data, w = 120, h = 32, color = "var(--accent)", fill = true }) => {
  const max = Math.max(...data, 1);
  const stepX = w / (data.length - 1);
  const pts = data.map((v, i) => `${i * stepX},${h - (v / max) * (h - 2) - 1}`).join(" ");
  const area = `0,${h} ${pts} ${w},${h}`;
  return (
    <svg width={w} height={h} style={{ display: "block" }}>
      {fill && <polygon points={area} fill={color} opacity="0.12" />}
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
};

// ---------- code block w/ syntax-ish highlight ----------
const CodeBlock = ({ code, lang = "python", highlightLines = [], showDiff = false }) => {
  const lines = code.split("\n");
  return (
    <div style={{
      fontFamily: "var(--fontMono)", fontSize: 13.5, lineHeight: 1.8,
      background: "var(--panelAlt)", border: "1px solid var(--border)", borderRadius: 8,
      overflow: "hidden",
    }}>
      <div style={{
        padding: "8px 14px", borderBottom: "1px solid var(--border)",
        display: "flex", justifyContent: "space-between",
        fontSize: 11, color: "var(--textMute)", letterSpacing: 0.6, textTransform: "uppercase",
      }}>
        <span>{lang}</span>
        <span>{lines.length} lines</span>
      </div>
      <pre style={{ margin: 0, padding: "12px 0", overflowX: "auto" }}>
        {lines.map((line, i) => {
          const isDiffHeader = showDiff && (line.startsWith("---") || line.startsWith("+++") || line.startsWith("@@"));
          if (isDiffHeader) return null;

          const isDiffMinus = showDiff && line.startsWith("-");
          const isDiffPlus  = showDiff && line.startsWith("+");
          const isHL = highlightLines.includes(i + 1);
          
          const displayLine = showDiff && line.length > 0 ? line.slice(1) : line;

          return (
            <div key={i} style={{
              display: "flex",
              background: isDiffMinus ? "color-mix(in oklab, var(--danger) 12%, transparent)"
                       : isDiffPlus  ? "color-mix(in oklab, var(--ok) 12%, transparent)"
                       : isHL        ? "color-mix(in oklab, var(--accent) 14%, transparent)"
                       : "transparent",
              borderLeft: isDiffMinus ? "2px solid var(--danger)"
                       : isDiffPlus  ? "2px solid var(--ok)"
                       : isHL        ? "2px solid var(--accent)" : "2px solid transparent",
            }}>
              <span style={{
                width: 36, textAlign: "right", paddingRight: 12,
                color: "var(--textMute)", userSelect: "none", flexShrink: 0,
              }}>{i + 1}</span>
              <span style={{
                color: isDiffMinus ? "var(--danger)" : isDiffPlus ? "var(--ok)" : "var(--text)",
                whiteSpace: "pre", paddingRight: 16,
              }}>{displayLine || " "}</span>
            </div>
          );
        })}
      </pre>
    </div>
  );
};

// ---------- panel + section ----------
const Panel = ({ title, action, children, style = {}, padding = 20 }) => (
  <div className="gl-panel" style={{
    background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 8,
    ...style,
  }}>
    {title && (
      <div style={{
        padding: "12px 18px", borderBottom: "1px solid var(--border)",
        display: "flex", justifyContent: "space-between", alignItems: "center",
        fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)",
        letterSpacing: 0.8, textTransform: "uppercase",
      }}>
        <span>{title}</span>
        {action}
      </div>
    )}
    <div style={{ padding }}>{children}</div>
  </div>
);

const Btn = ({ children, primary, ghost, onClick, icon, disabled, style = {}, type = "button" }) => (
  <button type={type} className="gl-btn" onClick={onClick} disabled={disabled} style={{
    display: "inline-flex", alignItems: "center", gap: 8,
    padding: "9px 16px", borderRadius: 6,
    fontFamily: "var(--fontUI)", fontSize: 13.5, fontWeight: 500,
    border: ghost ? "1px solid transparent"
          : primary ? `1px solid var(--accent)` : "1px solid var(--border)",
    background: primary ? "var(--accent)"
              : ghost ? "transparent" : "var(--panelAlt)",
    color: primary ? "#0a0b0e" : "var(--text)",
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
    transition: "all 120ms",
    ...style,
  }}>
    {icon && <Icon name={icon} size={15} />}
    {children}
  </button>
);

Object.assign(window, {
  THEMES, applyTheme, Icon, SeverityPill, Tag, StatusDot, Sparkline, CodeBlock, Panel, Btn,
});
