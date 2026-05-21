// Top-level app: shell, routing, theme picker.
// (Adapted from the Claude Design export — the original TweaksPanel relied on a
// claude.ai/design host protocol via window.parent.postMessage; we replace it
// with a small inline ThemePicker that just calls applyTheme on click.)
const { useState: uSA, useEffect: uEA } = React;

const NAV_PRIMARY = [
  { id: "overview", label: "Overview",  icon: "home" },
  { id: "live",     label: "Live scan", icon: "pulse", badge: "●" },
  { id: "scans",    label: "Findings",  icon: "list" },
];

const NAV_SECONDARY = [
  { id: "new",      label: "New scan",  icon: "play" },
  { id: "agents",   label: "Agents",    icon: "layers" },
  { id: "learning", label: "Learning",  icon: "book" },
];

const NAV_UTILITY = [
  { id: "settings", label: "Settings", icon: "cog" },
];

const DEFAULT_TWEAKS = {
  theme: "cyber",
  density: "comfortable",
  animSpeed: 1,
  showLoopback: true,
};

function App() {
  const [tweaks, setTweaks] = uSA(DEFAULT_TWEAKS);
  const setTweak = (k, v) => setTweaks(prev => ({ ...prev, [k]: v }));
  const [route, setRoute] = uSA("overview");
  const [routeArg, setRouteArg] = uSA(null);

  uEA(() => { applyTheme(tweaks.theme); }, [tweaks.theme]);

  const nav = (id, arg) => {
    setRoute(id);
    setRouteArg(arg);
    if (id === "learning" && arg) {
      setTimeout(() => window.__openLearningCwe && window.__openLearningCwe(arg), 50);
    }
  };

  const containerPad = tweaks.density === "compact" ? "20px 28px" : "32px 40px";
  const sidebarW = 220;

  const sectionLabel = {
    fontFamily: "var(--fontMono)", fontSize: 9,
    color: "var(--textMute)", textTransform: "uppercase",
    letterSpacing: 1.2, padding: "0 10px",
    marginBottom: 4, marginTop: 2,
  };

  const navButton = (n, dim) => (
    <button key={n.id} onClick={() => nav(n.id)} style={{
      display: "flex", alignItems: "center", gap: 10, padding: "8px 10px",
      background: route === n.id ? "var(--panelAlt)" : "transparent",
      border: "1px solid",
      borderColor: route === n.id ? "var(--border)" : "transparent",
      color: route === n.id ? "var(--text)" : dim ? "var(--textMute)" : "var(--textDim)",
      fontFamily: "var(--fontUI)", fontSize: 13, fontWeight: 500,
      borderRadius: 5, cursor: "pointer", textAlign: "left",
      transition: "all 120ms",
    }}>
      <Icon name={n.icon} size={14} />
      <span style={{ flex: 1 }}>{n.label}</span>
      {n.badge && <span style={{ color: "var(--accent)", fontSize: 8, animation: "gl-blink 1s infinite" }}>{n.badge}</span>}
    </button>
  );

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <aside style={{
        width: sidebarW, flexShrink: 0,
        background: "var(--panel)", borderRight: "1px solid var(--border)",
        display: "flex", flexDirection: "column", padding: "20px 12px",
        position: "sticky", top: 0, height: "100vh",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 8px 20px", borderBottom: "1px solid var(--border)", marginBottom: 12 }}>
          <div style={{
            width: 30, height: 30, borderRadius: 7,
            background: "linear-gradient(135deg, var(--accent), var(--accentDim))",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 0 16px color-mix(in oklab, var(--accent) 50%, transparent)",
          }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div>
            <div style={{ fontFamily: "var(--fontDisplay)", fontWeight: 700, fontSize: 14, lineHeight: 1.1 }}>GuardianLoop</div>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 9.5, color: "var(--textMute)", letterSpacing: 0.6, marginTop: 2 }}>v0.4.2 · day 2</div>
          </div>
        </div>

        <nav style={{ display: "flex", flexDirection: "column", gap: 2, flex: 1 }}>
          <div style={sectionLabel}>Primary</div>
          {NAV_PRIMARY.map(n => navButton(n, false))}

          <div style={{ borderTop: "1px solid var(--border)", margin: "8px 0" }} />

          <div style={sectionLabel}>Tools</div>
          {NAV_SECONDARY.map(n => navButton(n, true))}

          <div style={{ flex: 1 }} />

          <div style={{ borderTop: "1px solid var(--border)", margin: "4px 0" }} />
          {NAV_UTILITY.map(n => navButton(n, true))}
        </nav>

        <ThemePicker value={tweaks.theme} onChange={v => setTweak("theme", v)} />

        <div style={{ marginTop: 10, padding: 10, background: "var(--panelAlt)", border: "1px solid var(--border)", borderRadius: 5, fontSize: 11, fontFamily: "var(--fontMono)", color: "var(--textDim)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
            <StatusDot status="complete" />
            <span style={{ color: "var(--ok)" }}>all systems nominal</span>
          </div>
          <div style={{ color: "var(--textMute)", fontSize: 10 }}>
            api · 12ms<br/>
            sandbox · 2 idle<br/>
            nvd · 47/50 budget
          </div>
        </div>
      </aside>

      <main style={{ flex: 1, padding: containerPad, maxWidth: "calc(100vw - " + sidebarW + "px)", overflowX: "hidden" }}>
        {route === "overview"  && <OverviewScreen onNav={nav} />}
        {route === "live"      && <LiveScanScreen tweaks={tweaks} runId={routeArg} onNav={nav} onComplete={(run) => nav("detail", run)} />}
        {route === "new"       && <NewScanScreen onStart={(runId) => nav("live", runId)} />}
        {route === "scans"     && <FindingsScreen onNav={nav} />}
        {route === "detail"    && <ScanDetailScreen run={routeArg} onNav={nav} />}
        {route === "agents"    && <AgentsScreen />}
        {route === "learning"  && <LearningScreen />}
        {route === "settings"  && <SettingsScreen />}
      </main>
    </div>
  );
}

function ThemePicker({ value, onChange }) {
  const themes = ["cyber", "console", "editorial", "amber", "paper", "oceanic", "rosewood", "matrix"];
  return (
    <div style={{
      padding: 10, background: "var(--panelAlt)", border: "1px solid var(--border)",
      borderRadius: 5, marginBottom: 8,
    }}>
      <div style={{
        fontFamily: "var(--fontMono)", fontSize: 9.5, color: "var(--textMute)",
        textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6,
      }}>theme</div>
      <select value={value} onChange={e => onChange(e.target.value)} style={{
        width: "100%", padding: "5px 8px",
        background: "var(--panel)", border: "1px solid var(--border)",
        color: "var(--text)", fontFamily: "var(--fontMono)", fontSize: 11,
        borderRadius: 3, outline: "none", cursor: "pointer",
      }}>
        {themes.map(t => <option key={t} value={t}>{(THEMES[t] && THEMES[t].name) || t}</option>)}
      </select>
    </div>
  );
}

Object.assign(window, { App });
