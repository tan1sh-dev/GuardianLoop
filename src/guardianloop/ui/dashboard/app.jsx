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

  const containerPad = tweaks.density === "compact" ? "26px 36px" : "42px 52px";
  const sidebarW = 240;

  const sectionLabel = {
    fontFamily: "var(--fontMono)", fontSize: 10,
    color: "var(--textMute)", textTransform: "uppercase",
    letterSpacing: 1.5, padding: "0 12px",
    marginBottom: 8, marginTop: 8,
  };

  const navButton = (n, dim) => (
    <button key={n.id} onClick={() => nav(n.id)} className="gl-nav-btn" style={{
      display: "flex", alignItems: "center", gap: 12, padding: "10px 12px",
      background: route === n.id ? "var(--panelAlt)" : "transparent",
      border: "1px solid",
      borderColor: route === n.id ? "var(--border)" : "transparent",
      color: route === n.id ? "var(--text)" : dim ? "var(--textMute)" : "var(--textDim)",
      fontFamily: "var(--fontUI)", fontSize: 14.5, fontWeight: 500,
      borderRadius: 5, cursor: "pointer", textAlign: "left",
      transition: "all 120ms",
    }}>
      <Icon name={n.icon} size={16} />
      <span style={{ flex: 1 }}>{n.label}</span>
      {n.badge && <span style={{ color: "var(--accent)", fontSize: 8, animation: "gl-blink 1s infinite" }}>{n.badge}</span>}
    </button>
  );

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <aside style={{
        width: sidebarW, flexShrink: 0,
        background: "var(--panel)", borderRight: "1px solid var(--border)",
        display: "flex", flexDirection: "column", padding: "24px 16px",
        position: "sticky", top: 0, height: "100vh",
      }}>
        <div style={{ padding: "0 12px 24px", borderBottom: "1px solid var(--border)", marginBottom: 16 }}>
          <div style={{ fontFamily: "var(--fontDisplay)", fontWeight: 800, fontSize: 22, letterSpacing: "-0.8px", color: "var(--text)" }}>GuardianLoop</div>
        </div>

        <nav style={{ display: "flex", flexDirection: "column", gap: 8, flex: 1 }}>
          <div style={sectionLabel}>Primary</div>
          {NAV_PRIMARY.map(n => navButton(n, false))}

          <div style={{ borderTop: "1px solid var(--border)", margin: "16px 0" }} />

          <div style={sectionLabel}>Tools</div>
          {NAV_SECONDARY.map(n => navButton(n, true))}

          <div style={{ flex: 1 }} />

          <div style={{ borderTop: "1px solid var(--border)", margin: "16px 0" }} />
          {NAV_UTILITY.map(n => navButton(n, true))}
        </nav>

        <div style={{ marginTop: 14, padding: 12, background: "var(--panelAlt)", border: "1px solid var(--border)", borderRadius: 5, fontSize: 11, fontFamily: "var(--fontMono)", color: "var(--textDim)" }}>
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

      <main className="gl-main-content" key={route} style={{ flex: 1, padding: containerPad, maxWidth: "calc(100vw - " + sidebarW + "px)", overflowX: "hidden", position: "relative" }}>
        <div style={{ position: "absolute", top: tweaks.density === "compact" ? 20 : 32, right: tweaks.density === "compact" ? 30 : 44, zIndex: 100 }}>
          <a href="/" style={{
            display: "inline-flex", alignItems: "center", gap: 8,
            padding: "8px 16px", borderRadius: 8,
            background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)",
            color: "var(--textDim)", fontSize: 13, fontWeight: 600,
            textDecoration: "none", transition: "all 200ms ease"
          }}
          onMouseOver={e => { e.currentTarget.style.borderColor = "rgba(52,211,153,0.4)"; e.currentTarget.style.color = "var(--text)"; e.currentTarget.style.background = "rgba(52,211,153,0.08)"; }}
          onMouseOut={e => { e.currentTarget.style.borderColor = "var(--border)"; e.currentTarget.style.color = "var(--textDim)"; e.currentTarget.style.background = "rgba(255,255,255,0.03)"; }}
          >
            <Icon name="home" size={14} />
            Home
          </a>
        </div>

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

Object.assign(window, { App });
