// Overview, Findings, Scan Detail, New Scan, Settings
const { useState: uS1, useEffect: uE1, useRef: uRef1 } = React;

// ---------- Patch Viewer w/ Diff Toggle ----------
const PatchViewer = ({ patch, language }) => {
  const [showFull, setShowFull] = React.useState(false);

  return (
    <div>
      <div style={{
        display: "flex",
        flexWrap: "wrap",
        gap: 6,
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: 6,
      }}>
        <div style={{ flex: "1 1 auto", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--ok)", textTransform: "uppercase", letterSpacing: 1 }}>
          patched · {patch.model} · iteration {patch.iteration + 1}
        </div>
        <div style={{ display: "flex", gap: 4, background: "var(--panelAlt)", padding: 2, borderRadius: 5, border: "1px solid var(--border)" }}>
          <button
            onClick={() => setShowFull(false)}
            style={{
              background: !showFull ? "var(--borderStrong)" : "transparent",
              color: !showFull ? "var(--text)" : "var(--textMute)",
              border: "none",
              borderRadius: 3,
              fontSize: 10.5,
              padding: "2px 8px",
              fontFamily: "var(--fontMono)",
              cursor: "pointer",
              transition: "all 120ms",
            }}
          >
            diff
          </button>
          <button
            onClick={() => setShowFull(true)}
            style={{
              background: showFull ? "var(--borderStrong)" : "transparent",
              color: showFull ? "var(--text)" : "var(--textMute)",
              border: "none",
              borderRadius: 3,
              fontSize: 10.5,
              padding: "2px 8px",
              fontFamily: "var(--fontMono)",
              cursor: "pointer",
              transition: "all 120ms",
            }}
          >
            code at this step
          </button>
        </div>
      </div>
      {showFull ? (
        <CodeBlock code={patch.patched_code || ""} lang={language} highlightLines={[]} />
      ) : (
        <CodeBlock code={patch.diff || ""} lang="diff" showDiff={true} highlightLines={[]} />
      )}
    </div>
  );
};

// ========== OVERVIEW ==========
const OverviewScreen = ({ onNav }) => {
  const [runs, setRuns]       = uS1([]);
  const [loading, setLoading] = uS1(true);

  uE1(() => {
    let cancelled = false;
    fetch("/api/runs")
      .then(r => r.json())
      .then(data => { if (!cancelled) { setRuns(Array.isArray(data) ? data : []); setLoading(false); } })
      .catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const totalFindings = runs.reduce((a, r) => a + (r.findings || 0), 0);
  const totalPatched  = runs.reduce((a, r) => a + (r.patched  || 0), 0);
  const patchRate     = totalFindings > 0 ? ((totalPatched / totalFindings) * 100).toFixed(0) : "0";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div>
        <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", letterSpacing: 1.4, textTransform: "uppercase" }}>
          Security Console
        </div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 36, fontWeight: 600, margin: "8px 0 6px", letterSpacing: -0.6 }}>
          {loading
            ? "Loading…"
            : runs.length === 0
              ? <span>No scans yet. <span style={{ color: "var(--textDim)" }}>Submit your first target to start.</span></span>
              : <span>Dashboard. <span style={{ color: "var(--textDim)" }}>{totalFindings > 0 ? `${totalPatched} of ${totalFindings} findings auto-patched.` : "No findings on record."}</span></span>
          }
        </h1>
        <div style={{ color: "var(--textDim)", fontSize: 14 }}>
          {runs.length} run{runs.length !== 1 ? "s" : ""} total · {patchRate}% patch hold rate
        </div>
      </div>

      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        <KPICard label="total findings" value={totalFindings} delta={`${runs.length} runs`}  trend={TREND_14D}   color="var(--accent)" />
        <KPICard label="patches held"   value={totalPatched}  delta={`${patchRate}%`}        trend={PATCHED_14D} color="var(--ok)" />
        <KPICard label="scans run"      value={runs.length}   delta="all time"               trend={TREND_14D}   color="var(--accent2)" />
        <KPICard label="patch rate"     value={`${patchRate}%`} delta="held"                 trend={PATCHED_14D} color="var(--danger)" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
        {/* Recent runs */}
        <Panel title="recent runs" action={
          <Btn ghost icon="arrow" onClick={() => onNav("scans")}>view all</Btn>
        }>
          {loading ? (
            <div style={{ padding: "20px 14px", color: "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 12 }}>loading…</div>
          ) : runs.length === 0 ? (
            <div style={{ padding: "20px 14px", color: "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 12 }}>
              no runs yet — submit your first scan above
            </div>
          ) : (
            <div style={{ display: "grid", gap: 1, background: "var(--border)", border: "1px solid var(--border)", borderRadius: 4 }}>
              {runs.slice(0, 6).map(r => (
                <div key={r.id} onClick={() => onNav("detail", r)} style={{
                  display: "grid", gridTemplateColumns: "auto 1.5fr auto auto auto auto",
                  gap: 12, alignItems: "center", padding: "10px 14px",
                  background: "var(--panel)", cursor: "pointer", fontSize: 13,
                }}>
                  <StatusDot status={r.status} />
                  <div style={{ overflow: "hidden" }}>
                    <div style={{ fontFamily: "var(--fontMono)", color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.source}</div>
                    <div style={{ fontFamily: "var(--fontMono)", fontSize: 10.5, color: "var(--textMute)", marginTop: 2 }}>
                      {r.id} · {r.started_at ? new Date(r.started_at).toLocaleString() : ""}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 4 }}>
                    {(r.cwes || []).map(c => <Tag key={c} color="var(--textDim)">{c}</Tag>)}
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
          )}
        </Panel>

        {/* Quick actions + agent status */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <Panel title="quick start">
            <div style={{ display: "grid", gap: 8 }}>
              <Btn primary icon="play" onClick={() => onNav("new")}>Start a new scan</Btn>
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
      <Panel title="top weakness classes · reference">
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
const FindingsScreen = ({ onNav }) => {
  const [allFindings, setAllFindings] = uS1([]);
  const [loading, setLoading]         = uS1(true);
  const [filter, setFilter]           = uS1("all");
  const [q, setQ]                     = uS1("");

  uE1(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const runsRes = await fetch("/api/runs");
        if (!runsRes.ok) throw new Error("runs fetch failed");
        const runs = await runsRes.json();
        if (cancelled) return;
        const runsArr = Array.isArray(runs) ? runs : [];

        // Fetch all run details in parallel to get enriched findings
        const details = await Promise.all(
          runsArr.map(r => fetch(`/api/runs/${r.id}`).then(x => x.json()).catch(() => null))
        );
        if (cancelled) return;

        const findings = [];
        for (const detail of details) {
          if (!detail) continue;
          const runId   = detail.id;
          const enf     = Array.isArray(detail.enriched_findings) ? detail.enriched_findings : [];
          const verifs  = Array.isArray(detail.verifications)      ? detail.verifications      : [];
          const patches = Array.isArray(detail.patches)            ? detail.patches            : [];

          for (const ef of enf) {
            const f     = ef.finding || {};
            const verif = verifs.find(v => v.finding_id === f.id);
            const patch = patches.find(p => p.finding_id === f.id);

            let status = "unpatched";
            if (patch && verif && !verif.exploit_reproduced) status = "patched";
            else if (patch && verif && verif.exploit_reproduced) status = "exploitable";
            else if (patch) status = "patched";

            findings.push({
              id:       f.id || (runId + findings.length),
              run:      runId,
              file:     (f.file_path || "unknown").split(/[\\/]/).pop(),
              line:     f.line_start || 0,
              cwe:      f.cwe_id    || "unknown",
              severity: f.severity  || "unknown",
              cvss:     ef.cvss_score || 0,
              status,
              tool:     f.tool || "unknown",
            });
          }
        }
        if (!cancelled) setAllFindings(findings);
      } catch (_) {}
      if (!cancelled) setLoading(false);
    };
    load();
    return () => { cancelled = true; };
  }, []);

  const filtered = allFindings.filter(f => {
    if (filter !== "all" && f.status !== filter) return false;
    if (q && !`${f.file} ${f.cwe}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });

  const exportCsv = () => {
    const header = "run,cwe,severity,cvss,file,line,tool,status";
    const rows   = allFindings.map(f =>
      [f.run, f.cwe, f.severity, f.cvss, f.file, f.line, f.tool, f.status].join(",")
    );
    const blob = new Blob([header + "\n" + rows.join("\n")], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "guardianloop-findings.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const uniqueRuns = new Set(allFindings.map(f => f.run)).size;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 4px" }}>Findings library</h1>
        <div style={{ color: "var(--textDim)" }}>
          {loading
            ? "loading…"
            : `${allFindings.length} total findings across ${uniqueRuns} run${uniqueRuns !== 1 ? "s" : ""}`}
        </div>
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
        <Btn icon="download" onClick={exportCsv}>export csv</Btn>
      </div>

      {loading ? (
        <div style={{ padding: 40, textAlign: "center", color: "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 12 }}>
          loading findings…
        </div>
      ) : allFindings.length === 0 ? (
        <div style={{ padding: 40, textAlign: "center", color: "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 12 }}>
          no findings yet — submit your first scan
        </div>
      ) : (
        <div style={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
          <div style={{
            display: "grid", gridTemplateColumns: "auto 80px 2fr 70px 80px 110px 80px 24px",
            gap: 12, padding: "10px 14px", borderBottom: "1px solid var(--border)",
            fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 0.8,
          }}>
            <span>sev</span><span>cwe</span><span>file</span><span>line</span><span>tool</span><span>cvss</span><span>status</span><span></span>
          </div>
          {filtered.length === 0 ? (
            <div style={{ padding: "20px 14px", color: "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 12 }}>
              no findings match the current filter
            </div>
          ) : filtered.map(f => (
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
                  width: `${(f.cvss || 0) * 10}%`, height: 4, display: "inline-block",
                  background: f.cvss >= 9 ? "var(--danger)" : f.cvss >= 7 ? "var(--warn)" : "var(--info)",
                  marginRight: 6, verticalAlign: "middle",
                }} />
                <span style={{ color: "var(--textDim)" }}>{f.cvss || "—"}</span>
              </span>
              <span style={{ color: f.status === "patched" ? "var(--ok)" : "var(--danger)" }}>● {f.status}</span>
              <Icon name="chevron" size={12} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ========== SCAN DETAIL ==========
const ScanDetailScreen = ({ run, onNav }) => {
  const [detail, setDetail]   = uS1(null);
  const [loading, setLoading] = uS1(true);
  const [fetchErr, setFetchErr] = uS1(null);

  // run can arrive in two shapes:
  //   (a) { id, source, language, findings, patched, status, duration, cwes, started_at }
  //       — from OverviewScreen's "recent runs" row click
  //   (b) { id, summary, enriched_findings, verifications, patches, report_md }
  //       — from live-scan completion ("Open report" button)
  const runId = (run && run.id) || null;

  uE1(() => {
    if (!runId) { setLoading(false); return; }
    // If run already carries full detail (has enriched_findings array), use it directly
    if (run && Array.isArray(run.enriched_findings)) {
      setDetail(run);
      setLoading(false);
      return;
    }
    // Otherwise fetch from the API
    let cancelled = false;
    fetch(`/api/runs/${runId}`)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(data => { if (!cancelled) { setDetail(data); setLoading(false); } })
      .catch(e  => { if (!cancelled) { setFetchErr(e.message); setLoading(false); } });
    return () => { cancelled = true; };
  }, [runId]);

  // ---- helpers ----
  const downloadBlob = (content, filename, type) => {
    const blob = new Blob([content], { type });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMd = () => {
    if (detail && detail.report_md)
      downloadBlob(detail.report_md, `${runId}-report.md`, "text/markdown");
  };

  const downloadJson = () => {
    if (detail && detail.enriched_findings)
      downloadBlob(JSON.stringify(detail.enriched_findings, null, 2), `${runId}-findings.json`, "application/json");
  };

  const handleRerun = async () => {
    try {
      const r = await fetch(`/api/scan/rerun/${runId}`, { method: "POST" });
      if (r.ok) { const d = await r.json(); onNav("live", d.run_id); return; }
    } catch (_) {}
    onNav("new");
  };

  // ---- derived data ----
  const summary  = (detail && detail.summary) || {};
  const totals   = summary.totals || {};
  const enriched = Array.isArray(detail && detail.enriched_findings) ? detail.enriched_findings : [];
  const verifs   = Array.isArray(detail && detail.verifications)     ? detail.verifications     : [];
  const patches  = Array.isArray(detail && detail.patches)           ? detail.patches           : [];

  const displaySource = (() => {
    const raw = summary.source_file || (run && run.source) || runId || "";
    return raw.split(/[\\/]/).pop() || raw;
  })();
  const language = summary.language || (run && run.language) || "unknown";
  const findingsCount  = totals.findings  !== undefined ? totals.findings  : (run && run.findings);
  const patchesHeld    = totals.patches_held !== undefined ? totals.patches_held : (run && run.patched);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* ── header ── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div onClick={() => onNav("overview")} style={{
            fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textDim)",
            cursor: "pointer", marginBottom: 4,
          }}>
            ← all runs
          </div>
          <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 30, fontWeight: 600, margin: 0 }}>
            {displaySource}
          </h1>
          <div style={{ fontFamily: "var(--fontMono)", fontSize: 12, color: "var(--textDim)", marginTop: 4 }}>
            {runId} · {language}
            {findingsCount !== undefined ? ` · ${findingsCount} finding${findingsCount !== 1 ? "s" : ""}` : ""}
            {patchesHeld   !== undefined ? ` · ${patchesHeld} patch${patchesHeld !== 1 ? "es" : ""} held` : ""}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn icon="download" onClick={downloadMd}>report.md</Btn>
          <Btn icon="download" onClick={downloadJson}>findings.json</Btn>
          <Btn primary icon="refresh" onClick={handleRerun}>re-run</Btn>
        </div>
      </div>

      {/* ── loading / error states ── */}
      {loading && (
        <div style={{ padding: 40, textAlign: "center", color: "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 12 }}>
          loading run detail…
        </div>
      )}
      {fetchErr && (
        <div style={{
          padding: "10px 14px",
          background: "color-mix(in oklab, var(--danger) 10%, transparent)",
          border: "1px solid var(--danger)", borderRadius: 5,
          fontSize: 13, color: "var(--danger)",
        }}>
          Failed to load run: {fetchErr}
        </div>
      )}

      {/* ── one panel per finding ── */}
      {enriched.map((ef, idx) => {
        const f        = ef.finding || {};
        const patch    = patches.find(p => p.finding_id === f.id);
        const verif    = verifs.find(v => v.finding_id === f.id);
        const cweInfo  = CWE_BY_ID[f.cwe_id] || null;
        const name     = (cweInfo && cweInfo.name)  || f.cwe_id || "Unknown weakness";
        const what     = (cweInfo && cweInfo.what)  || ef.exploitability_summary || f.message || "—";
        const why      = (cweInfo && cweInfo.why)   || (patch && patch.reasoning_chain && patch.reasoning_chain[1]) || "—";
        const how      = (cweInfo && cweInfo.how)   || (patch && patch.reasoning_chain && patch.reasoning_chain[3]) || "—";

        return (
          <Panel key={f.id || idx} title={`finding ${idx + 1} of ${enriched.length} · ${f.cwe_id || "unknown"}`}>
            {/* ── finding header ── */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 16, marginBottom: 16 }}>
              <div>
                <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 22, fontWeight: 600, marginBottom: 6 }}>{name}</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {f.cwe_id   && <Tag color="var(--accent)">{f.cwe_id}</Tag>}
                  {(ef.cve_ids || []).slice(0, 3).map(c => <Tag key={c}>{c}</Tag>)}
                  {ef.cvss_score != null && <Tag color="var(--danger)">CVSS {ef.cvss_score}</Tag>}
                  {f.tool && f.rule_id && <Tag>{f.tool} · {f.rule_id}</Tag>}
                </div>
              </div>
              <SeverityPill severity={f.severity || "INFO"} />
            </div>

            {/* ── what / why / how ── */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 16 }}>
              {[{ label: "What", body: what }, { label: "Why", body: why }, { label: "How", body: how }].map(s => (
                <div key={s.label} style={{ borderTop: "2px solid var(--accent)", paddingTop: 10 }}>
                  <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--accent)", textTransform: "uppercase", letterSpacing: 1.4, marginBottom: 6 }}>{s.label}</div>
                  <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--textDim)" }}>{s.body}</div>
                </div>
              ))}
            </div>

            {/* ── vulnerable snippet + patch diff ── */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>
                  vulnerable · line {f.line_start}
                </div>
                <CodeBlock code={f.snippet || (cweInfo && cweInfo.vulnCode) || ""} lang={f.language || "python"} highlightLines={[]} />
              </div>
              {patch ? (
                <div style={{ minWidth: 0 }}>
                  <PatchViewer patch={patch} language={f.language || "python"} />
                </div>
              ) : (
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>
                    patch
                  </div>
                  <div style={{ padding: 12, background: "var(--panelAlt)", border: "1px solid var(--border)", borderRadius: 5, color: "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 12 }}>
                    no patch generated for this finding
                  </div>
                </div>
              )}
            </div>

            {/* ── inline verification result ── */}
            {verif && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: verif.exploit_reproduced ? "var(--danger)" : "var(--ok)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>
                  red-team · {verif.exploit_reproduced ? "patch failed" : "patch holds ✓"} · {verif.duration_seconds.toFixed(1)}s
                </div>
                <div style={{ background: "var(--panelAlt)", border: `1px solid ${verif.exploit_reproduced ? "var(--danger)" : "var(--border)"}`, borderRadius: 5, fontFamily: "var(--fontMono)", fontSize: 12 }}>
                  <div style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", color: "var(--textMute)", fontSize: 10, letterSpacing: 0.6 }}>
                    {verif.sandbox_exit_code === -1 ? "scout fallback (docker unavailable)" : "sandbox output"}
                  </div>
                  <div style={{ padding: 12 }}>
                    {verif.sandbox_stdout && (
                      <div style={{ color: "var(--textDim)", whiteSpace: "pre-wrap", marginBottom: 6 }}>{verif.sandbox_stdout}</div>
                    )}
                    {verif.sandbox_stderr && (
                      <div style={{ color: "var(--danger)", whiteSpace: "pre-wrap" }}>{verif.sandbox_stderr}</div>
                    )}
                    <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 6, color: verif.exploit_reproduced ? "var(--danger)" : "var(--ok)" }}>
                      <Icon name={verif.exploit_reproduced ? "x" : "check"} size={12} />
                      <span>{verif.exploit_reproduced ? "exploit reproduced · patch failed" : "exploit blocked · patch holds"}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </Panel>
        );
      })}

      {!loading && enriched.length === 0 && (
        <Panel>
          <div style={{ padding: 24, textAlign: "center", color: "var(--textMute)", fontFamily: "var(--fontMono)", fontSize: 12 }}>
            no findings for this run
          </div>
        </Panel>
      )}

      {/* ── Final Patched Code ── */}
      {patches.length > 0 && (
        <Panel title="final patched code (all fixes combined)">
          <div style={{ paddingBottom: 8, color: "var(--textDim)", fontSize: 13 }}>
            The fixer chains patches sequentially. This is the final source code with all fixes applied.
          </div>
          <CodeBlock code={patches[patches.length - 1].patched_code || ""} lang={language} />
        </Panel>
      )}

      {/* ── Fixer chain-of-thought ── */}
      {patches.length > 0 && (
        <Panel title="fixer · chain-of-thought">
          {patches.map((patch, pi) => (
            <div key={patch.finding_id || pi} style={{ marginBottom: pi < patches.length - 1 ? 20 : 0 }}>
              {patches.length > 1 && (
                <div style={{ fontFamily: "var(--fontMono)", fontSize: 10, color: "var(--textMute)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>
                  finding {(patch.finding_id || "").slice(0, 8)}
                </div>
              )}
              <ol style={{ paddingLeft: 20, margin: 0, color: "var(--textDim)", fontSize: 13.5, lineHeight: 1.7 }}>
                {(patch.reasoning_chain || []).map((step, i) => (
                  <li key={i}><span style={{ color: "var(--text)" }}>{step}</span></li>
                ))}
              </ol>
            </div>
          ))}
        </Panel>
      )}
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
const SUPPORTED_EXTS = new Set(["py", "c", "cc", "cpp", "cxx", "h", "hh", "hpp"]);

const NewScanScreen = ({ onStart }) => {
  const [mode, setMode]       = uS1("upload");
  const [code, setCode]       = uS1("");
  const [pr,   setPr]         = uS1("");
  const [drag, setDrag]       = uS1(false);
  const [loading, setLoading] = uS1(false);
  const [error,   setError]   = uS1(null);
  const fileInputRef          = uRef1(null);

  const startScan = async (url, opts = {}) => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(url, { method: "POST", ...opts });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.detail || `Server error (${r.status})`);
      onStart(data.run_id);
    } catch (e) {
      setError(e.message);
      setLoading(false);
    }
  };

  const handleFile = (file) => {
    if (!file) return;
    const ext = file.name.split(".").pop().toLowerCase();
    if (!SUPPORTED_EXTS.has(ext)) { setError("Unsupported file type — use .py, .c, or .cpp"); return; }
    if (file.size > 1_048_576)    { setError("File too large (max 1 MB)"); return; }
    const fd = new FormData();
    fd.append("file", file);
    startScan("/api/scan/upload", { body: fd });
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 880 }}>
      <div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 4px" }}>New scan</h1>
        <div style={{ color: "var(--textDim)" }}>Run the full pipeline: Scout → Classifier → Fixer → Red-Team → Report.</div>
      </div>

      <div style={{ display: "flex", gap: 6 }}>
        {[
          { id: "upload", label: "Upload file",   icon: "upload" },
          { id: "paste",  label: "Paste code",    icon: "code" },
          { id: "pr",     label: "GitHub PR URL", icon: "git" },
        ].map(m => (
          <Btn key={m.id} primary={mode === m.id} icon={m.icon}
               onClick={() => { setMode(m.id); setError(null); }}>
            {m.label}
          </Btn>
        ))}
      </div>

      {error && (
        <div style={{
          padding: "10px 14px",
          background: "color-mix(in oklab, var(--danger) 10%, transparent)",
          border: "1px solid var(--danger)", borderRadius: 5,
          fontSize: 13, color: "var(--danger)",
        }}>
          {error}
        </div>
      )}

      <Panel padding={20}>
        {/* ── Upload tab ── */}
        {mode === "upload" && (
          <div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".py,.c,.cc,.cpp,.cxx,.h,.hh,.hpp"
              style={{ display: "none" }}
              onChange={e => handleFile(e.target.files?.[0])}
            />
            <div
              onClick={() => !loading && fileInputRef.current?.click()}
              onDragOver={e => { e.preventDefault(); setDrag(true); }}
              onDragLeave={() => setDrag(false)}
              onDrop={e => {
                e.preventDefault(); setDrag(false);
                if (!loading) handleFile(e.dataTransfer.files?.[0]);
              }}
              style={{
                border: `1.5px dashed ${drag ? "var(--accent)" : "var(--borderStrong)"}`,
                borderRadius: 6, padding: "48px 24px", textAlign: "center",
                background: drag ? "color-mix(in oklab, var(--accent) 6%, transparent)" : "var(--panelAlt)",
                transition: "all 120ms", cursor: loading ? "wait" : "pointer",
              }}>
              <Icon name="upload" size={32} />
              <div style={{ fontFamily: "var(--fontDisplay)", fontSize: 18, fontWeight: 600, marginTop: 12 }}>
                {loading ? "Uploading…" : "Drop a .py or .cpp file here"}
              </div>
              <div style={{ color: "var(--textDim)", fontSize: 13, marginTop: 4 }}>
                {loading ? "Pipeline is starting…" : "or click to browse · max 1 MB"}
              </div>
            </div>
            <div style={{ marginTop: 14, display: "flex", justifyContent: "center" }}>
              <Btn primary={!loading} icon="play"
                   onClick={e => { e.stopPropagation(); if (!loading) startScan("/api/scan/demo"); }}>
                {loading ? "Running…" : "Use demo · samples/demo_sqli.py"}
              </Btn>
            </div>
          </div>
        )}

        {/* ── Paste tab ── */}
        {mode === "paste" && (
          <div>
            <textarea value={code} onChange={e => setCode(e.target.value)}
              placeholder="# paste python or c++ source…"
              style={{
                width: "100%", height: 280, padding: 14,
                fontFamily: "var(--fontMono)", fontSize: 13, lineHeight: 1.7,
                background: "var(--panelAlt)", border: "1px solid var(--border)", color: "var(--text)",
                borderRadius: 5, outline: "none", resize: "vertical", boxSizing: "border-box",
              }} />
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10 }}>
              <div style={{ display: "flex", gap: 6 }}>
                <Btn ghost onClick={() => setCode(VULN_PY)}>load CWE-89 sample</Btn>
                <Btn ghost onClick={() => setCode(VULN_CPP)}>load CWE-121 sample</Btn>
              </div>
              <Btn primary={!loading} icon="play" onClick={() => {
                if (!code.trim()) { setError("Paste some code first."); return; }
                startScan("/api/scan/paste", {
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ code }),
                });
              }}>
                {loading ? "Running…" : "Scan now"}
              </Btn>
            </div>
          </div>
        )}

        {/* ── GitHub PR tab ── */}
        {mode === "pr" && (
          <div>
            <div style={{ fontFamily: "var(--fontMono)", fontSize: 11, color: "var(--textMute)", marginBottom: 6 }}>
              github pull request url
            </div>
            <input value={pr} onChange={e => setPr(e.target.value)}
              placeholder="https://github.com/org/repo/pull/1234"
              style={{
                width: "100%", padding: "12px 14px",
                fontFamily: "var(--fontMono)", fontSize: 13,
                background: "var(--panelAlt)", border: "1px solid var(--border)", color: "var(--text)",
                borderRadius: 5, outline: "none", boxSizing: "border-box",
              }} />
            <div style={{ marginTop: 10, padding: 12, background: "var(--panelAlt)", border: "1px solid var(--border)", borderRadius: 5, fontSize: 12.5, color: "var(--textDim)" }}>
              <Icon name="shield" size={12} />{" "}
              Fetches changed <span style={{ fontFamily: "var(--fontMono)", color: "var(--text)" }}>.py / .cpp</span> files via GitHub API ·
              public repos work without a token · set{" "}
              <span style={{ fontFamily: "var(--fontMono)", color: "var(--accent)" }}>GITHUB_TOKEN</span>{" "}
              in <span style={{ fontFamily: "var(--fontMono)", color: "var(--accent)" }}>.env</span> for private repos.
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
              <Btn primary={!loading} icon="play" onClick={() => {
                if (!pr.trim()) { setError("Enter a GitHub PR URL."); return; }
                startScan("/api/scan/pr", {
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ url: pr }),
                });
              }}>
                {loading ? "Fetching PR…" : "Scan PR"}
              </Btn>
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
    scout:      { runs: "—", avgMs: "—",  lastRun: "—", model: "semgrep 1.62 + bandit 1.7.5" },
    classifier: { runs: "—", avgMs: "—",  lastRun: "—", model: "gemini-2.5-flash · NVD API" },
    fixer:      { runs: "—", avgMs: "—",  lastRun: "—", model: "gemini-2.5-pro · CoT k=5" },
    redteam:    { runs: "—", avgMs: "—",  lastRun: "—", model: "docker · semgrep fallback" },
    report:     { runs: "—", avgMs: "—",  lastRun: "—", model: "json + markdown writers" },
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 4px" }}>Agents</h1>
        <div style={{ color: "var(--textDim)" }}>Five pipeline nodes, one shared Pydantic state. All idle, all green.</div>
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
                <Stat2 label="runs"    value={s.runs} />
                <Stat2 label="avg dur" value={s.avgMs} />
                <Stat2 label="last"    value={s.lastRun} />
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
    fixer_model: "",
    classifier_model: "",
    max_loop_iterations: 3,
    sandbox_timeout_seconds: 30,
    nvd_api_key: "",
    google_api_key: "",
    google_api_key_2: "",
    google_api_key_3: "",
  });
  const [loading, setLoading] = uS1(true);
  const [saving, setSaving] = uS1(false);
  const [error, setError] = uS1(null);
  const [success, setSuccess] = uS1(false);

  const fetchConfig = () => {
    setLoading(true);
    fetch("/api/config")
      .then(r => {
        if (!r.ok) throw new Error("Failed to load configuration");
        return r.json();
      })
      .then(data => {
        setConfig(data);
        setError(null);
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  };

  uE1(() => {
    fetchConfig();
  }, []);

  const handleSave = () => {
    setSaving(true);
    setSuccess(false);
    setError(null);
    fetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config)
    })
      .then(r => {
        if (!r.ok) throw new Error("Failed to save configuration");
        return r.json();
      })
      .then(() => {
        setSuccess(true);
        // Refetch to get updated masked keys
        fetchConfig();
      })
      .catch(err => setError(err.message))
      .finally(() => setSaving(false));
  };

  const handleDiscard = () => {
    setSuccess(false);
    setError(null);
    fetchConfig();
  };

  if (loading) {
    return <div style={{ color: "var(--textDim)", padding: 32 }}>Loading settings...</div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 920 }}>
      <div>
        <h1 style={{ fontFamily: "var(--fontDisplay)", fontSize: 32, fontWeight: 600, margin: "0 0 4px" }}>Settings</h1>
        <div style={{ color: "var(--textDim)" }}>Mirrors <span style={{ fontFamily: "var(--fontMono)", color: "var(--accent)" }}>config.yaml</span> + <span style={{ fontFamily: "var(--fontMono)", color: "var(--accent)" }}>.env</span>. Changes regenerate the files on save.</div>
      </div>

      {error && (
        <div style={{ color: "#ef4444", background: "rgba(239, 68, 68, 0.1)", padding: 12, borderRadius: 4, fontSize: 13, border: "1px solid rgba(239, 68, 68, 0.2)" }}>
          {error}
        </div>
      )}

      {success && (
        <div style={{ color: "#10b981", background: "rgba(16, 185, 129, 0.1)", padding: 12, borderRadius: 4, fontSize: 13, border: "1px solid rgba(16, 185, 129, 0.2)" }}>
          Settings saved successfully!
        </div>
      )}

      <Panel title="models">
        <SettingRow label="fixer_model" desc="Chain-of-thought patch generation. Gemini 2.5 Pro recommended.">
          <Select value={config.fixer_model} onChange={v => setConfig({ ...config, fixer_model: v })}
            options={["gemini-2.5-pro", "gemini-2.5-flash"]} />
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
        <SettingRow label="GOOGLE_API_KEY" desc="Primary key used by Fixer + Classifier.">
          <MaskedInput value={config.google_api_key} onChange={v => setConfig({ ...config, google_api_key: v })} />
        </SettingRow>
        <SettingRow label="GOOGLE_API_KEY_2" desc="Rotation key 2 (optional fallback).">
          <MaskedInput value={config.google_api_key_2} onChange={v => setConfig({ ...config, google_api_key_2: v })} />
        </SettingRow>
        <SettingRow label="GOOGLE_API_KEY_3" desc="Rotation key 3 (optional fallback).">
          <MaskedInput value={config.google_api_key_3} onChange={v => setConfig({ ...config, google_api_key_3: v })} />
        </SettingRow>
        <SettingRow label="NVD_API_KEY" desc="Raises rate limit 5 → 50 / 30s.">
          <MaskedInput value={config.nvd_api_key} onChange={v => setConfig({ ...config, nvd_api_key: v })} />
        </SettingRow>
      </Panel>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Btn ghost onClick={handleDiscard} disabled={saving}>Discard</Btn>
        <Btn primary icon="check" onClick={handleSave} disabled={saving}>
          {saving ? "Saving..." : "Save changes"}
        </Btn>
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

const MaskedInput = ({ value, onChange }) => {
  const handleFocus = () => {
    if (value && value.includes("•")) {
      onChange("");
    }
  };
  return (
    <input 
      value={value} 
      onFocus={handleFocus}
      onChange={e => onChange(e.target.value)} 
      placeholder={value && value.includes("•") ? "••••••••••••" : "Enter new API key"}
      style={{
        padding: "7px 10px", background: "var(--panelAlt)", border: "1px solid var(--border)",
        color: "var(--text)", fontFamily: "var(--fontMono)", fontSize: 12, borderRadius: 4, width: 240,
      }} 
    />
  );
};

Object.assign(window, { OverviewScreen, FindingsScreen, ScanDetailScreen, NewScanScreen, AgentsScreen, SettingsScreen });
