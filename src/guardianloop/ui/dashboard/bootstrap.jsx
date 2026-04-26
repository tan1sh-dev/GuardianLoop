// Bootstrap — fetch live runs from /api/runs and override the mock data
// before App's first render. Falls back to mock data if the API is missing
// (e.g. opening the .html file directly off disk).
//
// RECENT_RUNS, ALL_FINDINGS, and SCAN_LOGS were attached to window by the
// design's data.jsx via Object.assign — we mutate those arrays in place so
// every component reads the new contents on first render.

(async function bootstrap() {
  function mutate(arr, replacement) {
    if (!Array.isArray(arr) || !Array.isArray(replacement)) return;
    arr.length = 0;
    arr.push(...replacement);
  }

  function timeAgo(iso) {
    if (!iso) return "";
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return iso;
    const diff = Math.max(0, Date.now() - t);
    const m = Math.round(diff / 60000);
    if (m < 1) return "just now";
    if (m < 60) return `${m} min ago`;
    const h = Math.round(m / 60);
    if (h < 24) return `${h} hr ago`;
    const d = Math.round(h / 24);
    return d === 1 ? "yesterday" : `${d}d ago`;
  }

  try {
    const r = await fetch("/api/runs", { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error("api unavailable");
    const runs = await r.json();
    if (Array.isArray(runs) && runs.length) {
      const normalized = runs.map(x => ({
        id: x.id,
        source: x.source,
        language: x.language || "unknown",
        findings: x.findings | 0,
        patched: x.patched | 0,
        status: x.status || "complete",
        duration: x.duration | 0,
        cwes: x.cwes || [],
        when: x.started_at ? timeAgo(x.started_at) : (x.when || ""),
      }));
      mutate(window.RECENT_RUNS, normalized);

      // Flatten run-level findings into the cross-run library if the API
      // bothered to emit them.
      const flatFindings = runs.flatMap(x => Array.isArray(x.findings_list) ? x.findings_list : []);
      if (flatFindings.length) mutate(window.ALL_FINDINGS, flatFindings);

      window.__guardianloop_live = true;
    }
  } catch (e) {
    // Silent fallback — mock data already in place.
    window.__guardianloop_live = false;
  }

  ReactDOM.createRoot(document.getElementById("root")).render(<App />);
})();
