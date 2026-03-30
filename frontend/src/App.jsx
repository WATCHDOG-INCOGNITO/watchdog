import { useState, useEffect, useCallback } from "react";

const API = "http://localhost:8000";

const COLORS = {
  bg: "#0a0e17",
  surface: "#111827",
  surface2: "#1a2332",
  border: "#1e2d3d",
  text: "#e2e8f0",
  textDim: "#64748b",
  accent: "#22d3ee",
  accentDim: "#0e7490",
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#64748b",
  confirmed: "#22d3ee",
  open: "#eab308",
  dismissed: "#64748b",
};

const severity = (s) =>
  ({ critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low, info: COLORS.info }[s] || COLORS.textDim);

function useFetch(url, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(() => {
    setLoading(true);
    fetch(`${API}${url}`)
      .then((r) => r.json())
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [url]);
  useEffect(() => { refresh(); }, [refresh, ...deps]);
  return { data, loading, refresh };
}

function Badge({ color, children }) {
  return (
    <span style={{
      background: color + "22", color, border: `1px solid ${color}44`,
      padding: "2px 10px", borderRadius: 4, fontSize: 11, fontWeight: 600,
      textTransform: "uppercase", letterSpacing: 0.5,
    }}>{children}</span>
  );
}

function Card({ children, style, onClick }) {
  return (
    <div onClick={onClick} style={{
      background: COLORS.surface, border: `1px solid ${COLORS.border}`,
      borderRadius: 8, padding: 16, ...style,
      cursor: onClick ? "pointer" : "default",
      transition: "border-color 0.2s",
    }}
    onMouseEnter={(e) => onClick && (e.currentTarget.style.borderColor = COLORS.accent)}
    onMouseLeave={(e) => onClick && (e.currentTarget.style.borderColor = COLORS.border)}
    >{children}</div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div style={{ textAlign: "center" }}>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || COLORS.accent, fontFamily: "'JetBrains Mono', monospace" }}>{value}</div>
      <div style={{ fontSize: 11, color: COLORS.textDim, marginTop: 4, textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
    </div>
  );
}

function Tab({ active, onClick, children }) {
  return (
    <button onClick={onClick} style={{
      background: active ? COLORS.accent + "18" : "transparent",
      color: active ? COLORS.accent : COLORS.textDim,
      border: `1px solid ${active ? COLORS.accent + "44" : "transparent"}`,
      padding: "8px 20px", borderRadius: 6, cursor: "pointer",
      fontSize: 13, fontWeight: 600, transition: "all 0.2s",
    }}>{children}</button>
  );
}

function NewScanModal({ onClose, onCreated }) {
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState("hybrid-lite");
  const [spa, setSpa] = useState(false);
  const [budget, setBudget] = useState(10);
  const [submitting, setSubmitting] = useState(false);

  const submit = async () => {
    if (!url) return;
    setSubmitting(true);
    try {
      const body = { target_url: url, mode, request_budget_total: budget };
      if (spa) body.config = { force_spa: true };
      const res = await fetch(`${API}/api/scan-runs/`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (data.run_id) {
        await fetch(`${API}/api/scan-runs/${data.run_id}/start/`, { method: "POST" });
        onCreated(data.run_id);
      }
    } catch (e) { console.error(e); }
    setSubmitting(false);
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "#000a", zIndex: 100,
      display: "flex", alignItems: "center", justifyContent: "center",
    }} onClick={onClose}>
      <Card style={{ width: 460, padding: 28 }} onClick={(e) => e.stopPropagation()}>
        <h2 style={{ color: COLORS.accent, fontSize: 18, margin: "0 0 20px", fontWeight: 700 }}>New Scan</h2>
        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: 12, color: COLORS.textDim, display: "block", marginBottom: 6 }}>Target URL</label>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com"
            style={{
              width: "100%", padding: "10px 12px", background: COLORS.bg, border: `1px solid ${COLORS.border}`,
              borderRadius: 6, color: COLORS.text, fontSize: 14, outline: "none", boxSizing: "border-box",
              fontFamily: "'JetBrains Mono', monospace",
            }} />
        </div>
        <div style={{ display: "flex", gap: 14, marginBottom: 14 }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, color: COLORS.textDim, display: "block", marginBottom: 6 }}>Mode</label>
            <select value={mode} onChange={(e) => setMode(e.target.value)} style={{
              width: "100%", padding: "10px 12px", background: COLORS.bg, border: `1px solid ${COLORS.border}`,
              borderRadius: 6, color: COLORS.text, fontSize: 13,
            }}>
              <option value="hybrid-lite">Hybrid Lite</option>
              <option value="hybrid-full">Hybrid Full</option>
              <option value="passive">Passive</option>
            </select>
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, color: COLORS.textDim, display: "block", marginBottom: 6 }}>Budget</label>
            <input type="number" value={budget} onChange={(e) => setBudget(Number(e.target.value))}
              style={{
                width: "100%", padding: "10px 12px", background: COLORS.bg, border: `1px solid ${COLORS.border}`,
                borderRadius: 6, color: COLORS.text, fontSize: 14, boxSizing: "border-box",
                fontFamily: "'JetBrains Mono', monospace",
              }} />
          </div>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 20, cursor: "pointer" }}>
          <input type="checkbox" checked={spa} onChange={(e) => setSpa(e.target.checked)} />
          <span style={{ fontSize: 13, color: COLORS.textDim }}>Force SPA mode (Playwright)</span>
        </label>
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button onClick={onClose} style={{
            padding: "8px 20px", background: "transparent", border: `1px solid ${COLORS.border}`,
            borderRadius: 6, color: COLORS.textDim, cursor: "pointer", fontSize: 13,
          }}>Cancel</button>
          <button onClick={submit} disabled={submitting || !url} style={{
            padding: "8px 24px", background: COLORS.accent, border: "none",
            borderRadius: 6, color: COLORS.bg, cursor: "pointer", fontSize: 13, fontWeight: 700,
            opacity: submitting || !url ? 0.5 : 1,
          }}>{submitting ? "Starting..." : "Start Scan"}</button>
        </div>
      </Card>
    </div>
  );
}

function ScanList({ scans, selected, onSelect, onRefresh }) {
  if (!scans) return <div style={{ color: COLORS.textDim, padding: 20 }}>Loading...</div>;
  return (
    <div>
      {(scans.results || scans).map((s) => (
        <Card key={s.run_id} onClick={() => onSelect(s.run_id)} style={{
          marginBottom: 8, borderLeft: `3px solid ${s.status === "running" ? COLORS.accent : s.status === "finished" ? COLORS.low : COLORS.textDim}`,
          background: selected === s.run_id ? COLORS.surface2 : COLORS.surface,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}>
                {s.target_url}
              </div>
              <div style={{ fontSize: 11, color: COLORS.textDim, marginTop: 4 }}>
                {s.run_id.slice(0, 8)}... · {new Date(s.created_at).toLocaleString()}
              </div>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {s.llm_calls_count > 0 && (
                <span style={{ fontSize: 11, color: COLORS.textDim }}>{s.llm_calls_count} calls · ${Number(s.llm_cost_usd).toFixed(2)}</span>
              )}
              <Badge color={s.status === "running" ? COLORS.accent : s.status === "finished" ? COLORS.low : COLORS.textDim}>
                {s.status}
              </Badge>
            </div>
          </div>
        </Card>
      ))}
    </div>
  );
}

function ScanDetail({ runId }) {
  const { data: scan, refresh } = useFetch(`/api/scan-runs/${runId}/`);
  const { data: summary } = useFetch(`/api/scan-runs/${runId}/summary/`);
  const { data: candidates } = useFetch(`/api/candidates/list/?run_id=${runId}`);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [findingDetail, setFindingDetail] = useState(null);

  useEffect(() => {
    if (scan?.status === "running") {
      const interval = setInterval(refresh, 5000);
      return () => clearInterval(interval);
    }
  }, [scan?.status, refresh]);

  useEffect(() => {
    if (selectedFinding) {
      fetch(`${API}/api/findings/${selectedFinding}/detail/`)
        .then((r) => r.json())
        .then(setFindingDetail);
    }
  }, [selectedFinding]);

  if (!scan) return null;

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 20 }}>
        <Card><Stat label="Status" value={scan.status} color={scan.status === "running" ? COLORS.accent : COLORS.low} /></Card>
        <Card><Stat label="Findings" value={summary?.total_findings || 0} color={COLORS.critical} /></Card>
        <Card><Stat label="LLM Calls" value={scan.llm_calls_count} /></Card>
        <Card><Stat label="Tokens" value={(scan.llm_tokens_used / 1000).toFixed(1) + "K"} /></Card>
        <Card><Stat label="Cost" value={"$" + Number(scan.llm_cost_usd).toFixed(2)} color={COLORS.medium} /></Card>
      </div>

      {scan.status === "running" && (
        <Card style={{ marginBottom: 16, borderLeft: `3px solid ${COLORS.accent}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 10, height: 10, borderRadius: "50%", background: COLORS.accent,
              animation: "pulse 1.5s infinite",
            }} />
            <span style={{ color: COLORS.accent, fontSize: 13 }}>Scanning in progress...</span>
            <button onClick={refresh} style={{
              marginLeft: "auto", padding: "4px 12px", background: COLORS.accent + "22",
              border: `1px solid ${COLORS.accent}44`, borderRadius: 4, color: COLORS.accent,
              cursor: "pointer", fontSize: 12,
            }}>Refresh</button>
          </div>
        </Card>
      )}

      {summary?.findings?.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <h3 style={{ color: COLORS.text, fontSize: 15, marginBottom: 10, fontWeight: 600 }}>
            Confirmed Findings ({summary.total_findings})
          </h3>
          {summary.findings.map((f) => (
            <Card key={f.finding_id} onClick={() => setSelectedFinding(f.finding_id)} style={{
              marginBottom: 6, background: selectedFinding === f.finding_id ? COLORS.surface2 : COLORS.surface,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                  <Badge color={severity(f.severity)}>{f.severity}</Badge>
                  <Badge color={COLORS.accent}>{f.vuln_type}</Badge>
                  <span style={{ fontSize: 13, color: COLORS.text }}>{f.title}</span>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: COLORS.textDim }}>{f.evidence_count} evidence</span>
                  <span style={{ fontSize: 13, color: COLORS.textDim }}>conf: {f.confidence}</span>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {selectedFinding && findingDetail && (
        <Card style={{ marginBottom: 20, borderLeft: `3px solid ${COLORS.accent}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <h3 style={{ color: COLORS.accent, fontSize: 15, margin: 0, fontWeight: 600 }}>Evidence Detail</h3>
            <button onClick={() => { setSelectedFinding(null); setFindingDetail(null); }} style={{
              background: "transparent", border: "none", color: COLORS.textDim, cursor: "pointer", fontSize: 18,
            }}>×</button>
          </div>
          <div style={{ fontSize: 13, color: COLORS.textDim, marginBottom: 8 }}>{findingDetail.summary}</div>
          {findingDetail.evidence?.map((ev, i) => {
            let content = ev.content;
            try { content = JSON.parse(ev.content); } catch {}
            return (
              <div key={ev.blob_id} style={{
                background: COLORS.bg, borderRadius: 6, padding: 12, marginBottom: 8,
                border: `1px solid ${ev.role === "primary" ? COLORS.accent + "44" : COLORS.border}`,
              }}>
                <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                  <Badge color={ev.role === "primary" ? COLORS.accent : COLORS.textDim}>{ev.role}</Badge>
                  <Badge color={COLORS.medium}>{ev.kind}</Badge>
                  {typeof content === "object" && content.attempt && (
                    <span style={{ fontSize: 11, color: COLORS.textDim }}>Attempt #{content.attempt}</span>
                  )}
                </div>
                {typeof content === "object" ? (
                  <div style={{ fontSize: 12 }}>
                    {content.payload && (
                      <div style={{ marginBottom: 6 }}>
                        <span style={{ color: COLORS.textDim }}>Payload: </span>
                        <code style={{ color: COLORS.critical, background: COLORS.critical + "15", padding: "2px 6px", borderRadius: 3, fontFamily: "'JetBrains Mono', monospace" }}>
                          {content.payload}
                        </code>
                      </div>
                    )}
                    {content.response_status && (
                      <div style={{ marginBottom: 6 }}>
                        <span style={{ color: COLORS.textDim }}>Status: </span>
                        <span style={{ color: content.response_status === 200 ? COLORS.low : COLORS.high }}>{content.response_status}</span>
                        {content.response_time && <span style={{ color: COLORS.textDim }}> · {content.response_time}s</span>}
                      </div>
                    )}
                    {content.llm_analysis && (
                      <div style={{ color: COLORS.text, fontSize: 12, lineHeight: 1.5, marginTop: 6, padding: 8, background: COLORS.surface, borderRadius: 4 }}>
                        {content.llm_analysis}
                      </div>
                    )}
                    {content.response_snippet && (
                      <details style={{ marginTop: 6 }}>
                        <summary style={{ color: COLORS.textDim, fontSize: 11, cursor: "pointer" }}>Response snippet</summary>
                        <pre style={{ fontSize: 11, color: COLORS.textDim, overflow: "auto", maxHeight: 150, marginTop: 4, padding: 8, background: COLORS.surface, borderRadius: 4, fontFamily: "'JetBrains Mono', monospace" }}>
                          {content.response_snippet}
                        </pre>
                      </details>
                    )}
                  </div>
                ) : (
                  <pre style={{ fontSize: 11, color: COLORS.textDim, overflow: "auto", maxHeight: 200, fontFamily: "'JetBrains Mono', monospace" }}>
                    {typeof content === "string" ? content : JSON.stringify(content, null, 2)}
                  </pre>
                )}
              </div>
            );
          })}
        </Card>
      )}

      {candidates?.candidates?.length > 0 && (
        <div>
          <h3 style={{ color: COLORS.text, fontSize: 15, marginBottom: 10, fontWeight: 600 }}>
            All Candidates ({candidates.candidates.length})
          </h3>
          <div style={{ maxHeight: 400, overflow: "auto" }}>
            {candidates.candidates.map((c) => (
              <Card key={c.cand_id} style={{ marginBottom: 4, padding: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <Badge color={c.status === "confirmed" ? COLORS.confirmed : c.status === "open" ? COLORS.open : COLORS.dismissed}>
                      {c.status}
                    </Badge>
                    <Badge color={severity("medium")}>{c.vuln_type}</Badge>
                    <span style={{ fontSize: 12, color: COLORS.text }}>{c.hypothesis?.slice(0, 60)}</span>
                  </div>
                  <span style={{ fontSize: 11, color: COLORS.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
                    {(c.priority_score * 100).toFixed(0)}%
                  </span>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function BenchmarkView({ runId }) {
  const { data } = useFetch(`/api/scan-runs/${runId}/summary/`);
  const { data: scan } = useFetch(`/api/scan-runs/${runId}/`);
  if (!data || !scan) return <div style={{ color: COLORS.textDim }}>Loading benchmark...</div>;

  const totalFindings = data.total_findings || 0;
  const tokensPerFinding = totalFindings > 0 ? Math.round(scan.llm_tokens_used / totalFindings) : 0;
  const costPerFinding = totalFindings > 0 ? (Number(scan.llm_cost_usd) / totalFindings).toFixed(3) : 0;

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
        <Card><Stat label="Total Findings" value={totalFindings} color={COLORS.critical} /></Card>
        <Card><Stat label="Tokens/Finding" value={tokensPerFinding.toLocaleString()} /></Card>
        <Card><Stat label="Cost/Finding" value={"$" + costPerFinding} color={COLORS.medium} /></Card>
        <Card><Stat label="Total Cost" value={"$" + Number(scan.llm_cost_usd).toFixed(2)} color={COLORS.high} /></Card>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Card>
          <h4 style={{ color: COLORS.text, fontSize: 13, margin: "0 0 12px", fontWeight: 600 }}>By Severity</h4>
          {Object.entries(data.by_severity || {}).map(([sev, count]) => (
            <div key={sev} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <Badge color={severity(sev)}>{sev}</Badge>
              <div style={{ flex: 1, margin: "0 12px", height: 6, background: COLORS.bg, borderRadius: 3, overflow: "hidden" }}>
                <div style={{
                  width: `${(count / totalFindings) * 100}%`, height: "100%",
                  background: severity(sev), borderRadius: 3,
                }} />
              </div>
              <span style={{ fontSize: 14, fontWeight: 700, color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}>{count}</span>
            </div>
          ))}
        </Card>
        <Card>
          <h4 style={{ color: COLORS.text, fontSize: 13, margin: "0 0 12px", fontWeight: 600 }}>By Type</h4>
          {Object.entries(data.by_vuln_type || {}).map(([type, count]) => (
            <div key={type} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <Badge color={COLORS.accent}>{type}</Badge>
              <div style={{ flex: 1, margin: "0 12px", height: 6, background: COLORS.bg, borderRadius: 3, overflow: "hidden" }}>
                <div style={{
                  width: `${(count / totalFindings) * 100}%`, height: "100%",
                  background: COLORS.accent, borderRadius: 3,
                }} />
              </div>
              <span style={{ fontSize: 14, fontWeight: 700, color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}>{count}</span>
            </div>
          ))}
        </Card>
      </div>

      <Card style={{ marginTop: 12 }}>
        <h4 style={{ color: COLORS.text, fontSize: 13, margin: "0 0 12px", fontWeight: 600 }}>Scan Stats</h4>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, fontSize: 12 }}>
          <div><span style={{ color: COLORS.textDim }}>Target: </span><span style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}>{scan.target_url}</span></div>
          <div><span style={{ color: COLORS.textDim }}>Duration: </span><span style={{ color: COLORS.text }}>
            {scan.finished_at ? Math.round((new Date(scan.finished_at) - new Date(scan.created_at)) / 1000) + "s" : "running"}
          </span></div>
          <div><span style={{ color: COLORS.textDim }}>Requests: </span><span style={{ color: COLORS.text }}>{scan.request_budget_used}</span></div>
          <div><span style={{ color: COLORS.textDim }}>LLM Calls: </span><span style={{ color: COLORS.text }}>{scan.llm_calls_count}</span></div>
          <div><span style={{ color: COLORS.textDim }}>Tokens: </span><span style={{ color: COLORS.text }}>{scan.llm_tokens_used.toLocaleString()}</span></div>
          <div><span style={{ color: COLORS.textDim }}>Mode: </span><span style={{ color: COLORS.text }}>{scan.mode}</span></div>
        </div>
      </Card>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState("scans");
  const [selectedRun, setSelectedRun] = useState(null);
  const [showNewScan, setShowNewScan] = useState(false);
  const { data: scans, refresh: refreshScans } = useFetch("/api/scan-runs/");

  return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", color: COLORS.text, fontFamily: "'Inter', -apple-system, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap');
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: ${COLORS.bg}; }
        ::-webkit-scrollbar-thumb { background: ${COLORS.border}; border-radius: 3px; }
      `}</style>

      <header style={{
        padding: "14px 28px", borderBottom: `1px solid ${COLORS.border}`,
        display: "flex", justifyContent: "space-between", alignItems: "center",
        background: COLORS.surface,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 20, fontWeight: 700, color: COLORS.accent, letterSpacing: -0.5 }}>WATCHDOG</span>
          <span style={{ fontSize: 11, color: COLORS.textDim, background: COLORS.bg, padding: "2px 8px", borderRadius: 4 }}>v2.0</span>
        </div>
        <button onClick={() => setShowNewScan(true)} style={{
          padding: "8px 20px", background: COLORS.accent, border: "none",
          borderRadius: 6, color: COLORS.bg, cursor: "pointer", fontSize: 13, fontWeight: 700,
        }}>+ New Scan</button>
      </header>

      <div style={{ display: "flex", height: "calc(100vh - 53px)" }}>
        <aside style={{
          width: 340, borderRight: `1px solid ${COLORS.border}`, padding: 16,
          overflow: "auto", background: COLORS.surface + "80",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <span style={{ fontSize: 12, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: 1 }}>Scan History</span>
            <button onClick={refreshScans} style={{
              background: "transparent", border: "none", color: COLORS.textDim, cursor: "pointer", fontSize: 16,
            }}>↻</button>
          </div>
          <ScanList scans={scans} selected={selectedRun} onSelect={setSelectedRun} onRefresh={refreshScans} />
        </aside>

        <main style={{ flex: 1, padding: 24, overflow: "auto" }}>
          {selectedRun ? (
            <>
              <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
                <Tab active={tab === "scans"} onClick={() => setTab("scans")}>Results</Tab>
                <Tab active={tab === "benchmark"} onClick={() => setTab("benchmark")}>Benchmark</Tab>
              </div>
              {tab === "scans" && <ScanDetail runId={selectedRun} />}
              {tab === "benchmark" && <BenchmarkView runId={selectedRun} />}
            </>
          ) : (
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              height: "100%", color: COLORS.textDim, fontSize: 14,
            }}>
              Select a scan or create a new one
            </div>
          )}
        </main>
      </div>

      {showNewScan && (
        <NewScanModal
          onClose={() => setShowNewScan(false)}
          onCreated={(id) => { setShowNewScan(false); setSelectedRun(id); refreshScans(); }}
        />
      )}
    </div>
  );
}
