import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./App.css";

const API_BASE = process.env.REACT_APP_API_BASE || "";
const WS_BASE = API_BASE.replace(/^http/i, "ws");
const STALE_AFTER_MS = 20000;

const STATUS_META = {
  queued: { label: "대기 중", tone: "queued", copy: "시작 요청을 기다리는 상태입니다." },
  running: { label: "실행 중", tone: "running", copy: "백엔드가 작업을 계속 기록하고 있습니다." },
  finished: { label: "완료", tone: "finished", copy: "스캔이 정상적으로 끝났습니다." },
  failed: { label: "실패", tone: "failed", copy: "실행 중 오류가 발생해 중단되었습니다." },
  stopped: { label: "중지됨", tone: "stopped", copy: "사용자 요청으로 실행이 중지되었습니다." },
  stale: { label: "응답 없음", tone: "stale", copy: "최근 백엔드 활동이 없어 현재 상태를 신뢰하기 어렵습니다." },
};

function apiUrl(path) {
  return `${API_BASE}${path}`;
}

function wsUrl(path) {
  return `${WS_BASE}${path}`;
}

async function readJson(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: text };
  }
}

async function apiGet(path) {
  const response = await fetch(apiUrl(path));
  const payload = await readJson(response);
  if (!response.ok) {
    throw new Error(payload.error || payload.detail || `HTTP ${response.status}`);
  }
  return payload;
}

async function apiPost(path, body) {
  const response = await fetch(apiUrl(path), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await readJson(response);
  if (!response.ok) {
    throw new Error(payload.error || payload.detail || `HTTP ${response.status}`);
  }
  return payload;
}

function formatDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("ko-KR");
}

function formatCount(value) {
  return Number(value || 0).toLocaleString("ko-KR");
}

function formatCompactCount(value) {
  const amount = Number(value || 0);
  if (amount >= 1000000) return `${(amount / 1000000).toFixed(1)}M`;
  if (amount >= 1000) return `${(amount / 1000).toFixed(1)}K`;
  return formatCount(amount);
}

function formatCurrency(value) {
  return `$${Number(value || 0).toFixed(2)}`;
}

function formatSeconds(totalSeconds) {
  const seconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remain = seconds % 60;
  if (hours > 0) return `${hours}시간 ${minutes}분`;
  if (minutes > 0) return `${minutes}분 ${remain}초`;
  return `${remain}초`;
}

function formatRuntime(scan, now) {
  if (!scan?.created_at) return "-";
  const start = new Date(scan.created_at).getTime();
  const end = scan.finished_at ? new Date(scan.finished_at).getTime() : now;
  return formatSeconds((end - start) / 1000);
}

function formatAgo(dateValue, now) {
  if (!dateValue) return "-";
  const diff = Math.max(0, Math.floor((now - new Date(dateValue).getTime()) / 1000));
  if (diff < 60) return `${diff}초 전`;
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  return `${Math.floor(diff / 3600)}시간 전`;
}

function normalizePaginatedList(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.scans)) return payload.scans;
  if (Array.isArray(payload?.candidates)) return payload.candidates;
  if (Array.isArray(payload?.findings)) return payload.findings;
  return [];
}

function getScanEngine(scan) {
  return scan?.config?.mode === "mcp" ? "MCP 에이전트" : "구조화 파이프라인";
}

function isScanStale(scan, now) {
  if (!scan || scan.status !== "running" || !scan.updated_at) return false;
  return now - new Date(scan.updated_at).getTime() > STALE_AFTER_MS;
}

function getEffectiveStatus(scan, now) {
  if (!scan) return STATUS_META.queued;
  if (isScanStale(scan, now)) return STATUS_META.stale;
  return STATUS_META[scan.status] || STATUS_META.queued;
}

async function fetchScanListSnapshot() {
  const payload = await apiGet("/api/scan-runs/?page_size=100");
  return { scans: normalizePaginatedList(payload), emitted_at: new Date().toISOString() };
}

async function fetchScanRunSnapshot(runId) {
  const [scan, summary, candidatesPayload, requestsPayload] = await Promise.all([
    apiGet(`/api/scan-runs/${runId}/`),
    apiGet(`/api/scan-runs/${runId}/summary/`),
    apiGet(`/api/candidates/list/?run_id=${runId}&page_size=100`),
    apiGet(`/api/request-catalog/list/?run_id=${runId}&page_size=1`),
  ]);
  const candidates = normalizePaginatedList(candidatesPayload);
  return {
    run_id: runId,
    emitted_at: new Date().toISOString(),
    scan,
    summary,
    candidates,
    candidate_count: candidatesPayload.count ?? candidates.length,
    request_catalog_count: requestsPayload.count ?? 0,
  };
}

async function fetchFindingDetail(findingId) {
  return apiGet(`/api/findings/${findingId}/detail/`);
}

async function fetchLlmTraces(runId) {
  const payload = await apiGet(`/api/scan-runs/${runId}/llm-traces/?page_size=100`);
  return { traces: normalizePaginatedList(payload), count: payload.count ?? normalizePaginatedList(payload).length };
}

function EmptyState({ title, body, className = "" }) {
  return (
    <div className={`empty-state ${className}`.trim()}>
      <strong>{title}</strong>
      <p>{body}</p>
    </div>
  );
}

function StatusPill({ scan, now }) {
  const meta = getEffectiveStatus(scan, now);
  return <span className={`status-pill tone-${meta.tone}`}>{meta.label}</span>;
}

function SectionCard({ title, kicker, actions, children }) {
  return (
    <section className="section-card">
      <div className="section-head">
        <div>
          {kicker ? <div className="section-kicker">{kicker}</div> : null}
          <h2>{title}</h2>
        </div>
        {actions ? <div className="section-actions">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

function StatCard({ label, value, helper, tone = "neutral", onClick, actionLabel }) {
  const content = (
    <>
      <div className="stat-label-row">
        <span className="stat-label">{label}</span>
        {actionLabel ? <span className="stat-action">{actionLabel}</span> : null}
      </div>
      <div className="stat-value">{value}</div>
      {helper ? <div className="stat-helper">{helper}</div> : null}
    </>
  );

  if (onClick) {
    return (
      <button type="button" className={`stat-card stat-card-button tone-${tone}`} onClick={onClick}>
        {content}
      </button>
    );
  }

  return <div className={`stat-card tone-${tone}`}>{content}</div>;
}

function CandidateItem({ candidate }) {
  return (
    <div className="candidate-row">
      <div className="candidate-header">
        <span className={`candidate-status status-${candidate.status}`}>{candidate.status}</span>
        <span className="type-pill">{candidate.vuln_type || "unknown"}</span>
        <span className="candidate-score">{Math.round((candidate.priority_score || 0) * 100)}점</span>
      </div>
      <div className="candidate-hypothesis">{candidate.hypothesis || "설명이 없습니다."}</div>
      <div className="candidate-endpoint">
        {candidate.method || "-"} {candidate.endpoint || "-"}
      </div>
    </div>
  );
}

function FindingDetailPanel({ finding, detail }) {
  if (!finding) {
    return <EmptyState title="취약점을 선택하세요" body="왼쪽 목록에서 항목을 선택하면 상세 설명과 증거를 확인할 수 있습니다." />;
  }

  return (
    <div className="artifact-modal-detail">
      <div className="detail-headline">
        <span className={`severity-pill severity-${finding.severity}`}>{finding.severity}</span>
        <span className="type-pill">{finding.vuln_type || "unknown"}</span>
        <h3>{finding.title}</h3>
      </div>
      <p className="finding-subtitle">신뢰도 {finding.confidence} | 증거 {finding.evidence_count || 0}건</p>

      {detail?.summary ? (
        <div className="llm-analysis">
          <strong>요약</strong>
          <p>{detail.summary}</p>
        </div>
      ) : null}

      {detail?.reproduction_steps ? (
        <div className="detail-summary">
          <strong>재현 절차</strong>
          <pre className="detail-steps">{detail.reproduction_steps}</pre>
        </div>
      ) : null}

      {detail?.evidence?.length ? (
        <div className="evidence-grid">
          {detail.evidence.map((item) => (
            <div key={item.blob_id} className="evidence-card">
              <div className="evidence-head">
                <span className="type-pill">{item.kind}</span>
                <span className="type-pill">{item.role}</span>
              </div>
              <pre>{typeof item.content === "string" ? item.content : JSON.stringify(item.content, null, 2)}</pre>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState title="증거가 없습니다" body="이 취약점에는 아직 저장된 증거가 없습니다." />
      )}
    </div>
  );
}

function FindingsModal({ findings, detail, loading, error, selectedFindingId, onSelect, onClose }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card modal-card-wide" onClick={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <div className="section-kicker">보안 결과</div>
            <h2>취약점 목록</h2>
          </div>
          <button type="button" className="ghost-button" onClick={onClose}>닫기</button>
        </div>

        {error ? <div className="callout callout-error">{error}</div> : null}

        {findings.length ? (
          <div className="artifact-modal-grid">
            <div className="artifact-modal-list">
              {findings.map((finding) => (
                <button
                  key={finding.finding_id}
                  type="button"
                  className={`finding-row ${selectedFindingId === finding.finding_id ? "active" : ""}`}
                  onClick={() => onSelect(finding.finding_id)}
                >
                  <div className="candidate-header">
                    <span className={`severity-pill severity-${finding.severity}`}>{finding.severity}</span>
                    <span className="type-pill">{finding.vuln_type || "unknown"}</span>
                    <span className="finding-evidence-count">{finding.evidence_count || 0} evidence</span>
                  </div>
                  <div className="finding-title">{finding.title}</div>
                </button>
              ))}
            </div>

            {loading ? (
              <EmptyState title="상세 정보를 불러오는 중입니다" body="선택한 취약점의 증거와 요약을 가져오고 있습니다." />
            ) : (
              <FindingDetailPanel
                finding={findings.find((item) => item.finding_id === selectedFindingId)}
                detail={detail}
              />
            )}
          </div>
        ) : (
          <EmptyState title="확정된 취약점이 없습니다" body="현재 실행에는 저장된 취약점이 없습니다." />
        )}
      </div>
    </div>
  );
}

function CandidatesModal({ candidates, onClose }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card modal-card-wide" onClick={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <div className="section-kicker">분석 후보</div>
            <h2>가설 목록</h2>
          </div>
          <button type="button" className="ghost-button" onClick={onClose}>닫기</button>
        </div>

        {candidates.length ? (
          <div className="list-stack modal-list-stack">
            {candidates.map((candidate) => <CandidateItem key={candidate.cand_id} candidate={candidate} />)}
          </div>
        ) : (
          <EmptyState title="저장된 가설이 없습니다" body="현재 실행에는 저장된 가설이 없습니다." />
        )}
      </div>
    </div>
  );
}

function RunDetailsModal({ scan, requestCount, candidateCount, onClose }) {
  if (!scan) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card modal-card-wide" onClick={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <div className="section-kicker">실행 정보</div>
            <h2>스캔 상세</h2>
          </div>
          <button type="button" className="ghost-button" onClick={onClose}>닫기</button>
        </div>

        <div className="detail-grid detail-grid-compact">
          <div><span>Run ID</span><strong>{scan.run_id}</strong></div>
          <div><span>상태</span><strong>{scan.status}</strong></div>
          <div><span>엔진</span><strong>{getScanEngine(scan)}</strong></div>
          <div><span>생성 시각</span><strong>{formatDateTime(scan.created_at)}</strong></div>
          <div><span>최근 갱신</span><strong>{formatDateTime(scan.updated_at)}</strong></div>
          <div><span>종료 시각</span><strong>{formatDateTime(scan.finished_at)}</strong></div>
          <div><span>요청 예산</span><strong>{formatCount(scan.request_budget_used)} / {formatCount(scan.request_budget_total)}</strong></div>
          <div><span>요청 수</span><strong>{formatCount(requestCount)}</strong></div>
          <div><span>가설 수</span><strong>{formatCount(candidateCount)}</strong></div>
          <div><span>LLM 호출</span><strong>{formatCount(scan.llm_calls_count)}</strong></div>
          <div><span>토큰</span><strong>{formatCount(scan.llm_tokens_used)}</strong></div>
          <div><span>비용</span><strong>{formatCurrency(scan.llm_cost_usd)}</strong></div>
        </div>

        {scan.error_log ? (
          <div className="failure-panel">
            <strong>실패 로그</strong>
            <pre className="failure-log">{scan.error_log}</pre>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function LlmTraceModal({ scan, traces, loading, error, onRefresh, onClose }) {
  const [expandedTraceId, setExpandedTraceId] = useState(null);

  if (!scan) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card modal-card-wide" onClick={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <div className="section-kicker">LLM 기록</div>
            <h2>모델 호출 목록</h2>
          </div>
          <div className="modal-actions">
            <button type="button" className="ghost-button" onClick={onRefresh}>새로고침</button>
            <button type="button" className="ghost-button" onClick={onClose}>닫기</button>
          </div>
        </div>

        <p className="modal-copy">{scan.target_url} 에서 발생한 모델 호출 목록입니다. 필요한 호출만 아래로 펼쳐서 보면 됩니다.</p>

        {error ? <div className="callout callout-error">{error}</div> : null}
        {loading ? <div className="callout callout-neutral">LLM 기록을 불러오는 중입니다...</div> : null}

        {traces.length ? (
          <div className="trace-list">
            {traces.map((trace) => {
              const isOpen = expandedTraceId === trace.trace_id;
              return (
                <article key={trace.trace_id} className={`trace-row trace-row-stack ${isOpen ? "is-expanded" : ""}`}>
                  <div className="trace-row-head">
                    <div className="trace-row-main">
                      <div className="trace-card-title">
                        <span className="type-pill">호출 #{trace.call_index || "-"}</span>
                        <strong>{trace.stage || "analysis"}</strong>
                      </div>
                      <div className="trace-card-meta">
                        <span>{formatDateTime(trace.created_at)}</span>
                        <span>{trace.model || "-"}</span>
                      </div>
                    </div>
                    <div className="trace-row-actions">
                      {trace.error ? <span className="trace-row-error">오류 있음</span> : null}
                      <button
                        type="button"
                        className="trace-expand-button"
                        onClick={() => setExpandedTraceId(isOpen ? null : trace.trace_id)}
                      >
                        {isOpen ? "▲ 접기" : "▼ 자세히 보기"}
                      </button>
                    </div>
                  </div>

                  <div className={`trace-inline-detail ${isOpen ? "is-open" : ""}`}>
                    <div className="trace-inline-detail-inner">
                      <div className="trace-summary-grid">
                        <div><span>입력 토큰</span><strong>{formatCount(trace.input_tokens)}</strong></div>
                        <div><span>출력 토큰</span><strong>{formatCount(trace.output_tokens)}</strong></div>
                        <div><span>중단 사유</span><strong>{trace.stop_reason || "-"}</strong></div>
                      </div>

                      {trace.error ? (
                        <div className="callout callout-error">
                          <strong>호출 오류</strong>
                          <div>{trace.error}</div>
                        </div>
                      ) : null}

                      <div className="trace-detail-sections">
                        <div className="trace-block">
                          <div className="trace-block-head"><div className="mini-title">요청 요약</div></div>
                          <pre>{trace.prompt_preview || "저장된 요청 요약이 없습니다."}</pre>
                        </div>
                        <div className="trace-block">
                          <div className="trace-block-head"><div className="mini-title">응답 요약</div></div>
                          <pre>{trace.response_preview || "저장된 응답 요약이 없습니다."}</pre>
                        </div>
                      </div>

                      {trace.tool_calls?.length ? (
                        <div className="trace-tools">
                          <div className="mini-title">도구 호출</div>
                          <div className="trace-tool-list">
                            {trace.tool_calls.map((toolCall, index) => (
                              <div key={`${trace.trace_id}-tool-${index}`} className="trace-tool-card">
                                <strong>{toolCall.name || `tool_${index + 1}`}</strong>
                                <pre>{JSON.stringify(toolCall.input || {}, null, 2)}</pre>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : null}

                      {trace.metadata?.tool_results?.length ? (
                        <div className="trace-tools">
                          <div className="mini-title">도구 응답 요약</div>
                          <div className="trace-tool-list">
                            {trace.metadata.tool_results.map((toolResult, index) => (
                              <div key={`${trace.trace_id}-tool-result-${index}`} className="trace-tool-card">
                                <strong>{toolResult.tool_use_id || `result_${index + 1}`}</strong>
                                <pre>{toolResult.content || "기록된 응답이 없습니다."}</pre>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        ) : (
          !loading ? <EmptyState title="저장된 LLM 기록이 없습니다" body="이 실행에서는 아직 모델 호출 기록이 저장되지 않았습니다." /> : null
        )}
      </div>
    </div>
  );
}

function NewScanModal({ onClose, onCreated }) {
  const [targetUrl, setTargetUrl] = useState("");
  const [requestBudget, setRequestBudget] = useState(10);
  const [forceSpa, setForceSpa] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit() {
    if (!targetUrl.trim()) return;
    setSubmitting(true);
    setError("");

    try {
      const config = { mode: "mcp" };
      if (forceSpa) config.force_spa = true;

      const created = await apiPost("/api/scan-runs/", {
        target_url: targetUrl.trim(),
        mode: "hybrid-lite",
        request_budget_total: Number(requestBudget) || 10,
        config,
      });

      await apiPost(`/api/scan-runs/${created.run_id}/start/`);
      onCreated(created.run_id);
    } catch (submitError) {
      setError(submitError.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <div className="section-kicker">새 스캔</div>
            <h2>MCP 스캔 생성</h2>
          </div>
          <button type="button" className="ghost-button" onClick={onClose}>닫기</button>
        </div>

        <p className="modal-copy">새 실행은 MCP 에이전트 모드로 생성됩니다.</p>
        {error ? <div className="callout callout-error">{error}</div> : null}

        <label className="field">
          <span>대상 URL</span>
          <input value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="https://example.com" />
        </label>

        <label className="field">
          <span>요청 예산</span>
          <input type="number" min="1" value={requestBudget} onChange={(event) => setRequestBudget(event.target.value)} />
        </label>

        <label className="checkbox-row">
          <input type="checkbox" checked={forceSpa} onChange={(event) => setForceSpa(event.target.checked)} />
          <span>SPA 모드 강제 사용</span>
        </label>

        <div className="modal-actions" style={{ marginTop: 18 }}>
          <button type="button" className="ghost-button" onClick={onClose}>취소</button>
          <button type="button" className="primary-button" disabled={submitting || !targetUrl.trim()} onClick={handleSubmit}>
            {submitting ? "시작 중..." : "새 스캔"}
          </button>
        </div>
      </div>
    </div>
  );
}

function ScanCard({ scan, selected, onSelect, now, compact }) {
  const statusMeta = getEffectiveStatus(scan, now);

  return (
    <article className={`scan-card ${selected ? "selected" : ""} ${compact ? "scan-card-compact" : ""}`}>
      <button type="button" className="scan-card-main" onClick={() => onSelect(scan.run_id)}>
        <div className="scan-card-head">
          <div className="hero-badges">
            <span className={`status-pill tone-${statusMeta.tone}`}>{statusMeta.label}</span>
            <span className="scan-engine">{getScanEngine(scan)}</span>
          </div>

          <div className="scan-card-top-metrics">
            <span>{formatCount(scan.llm_calls_count)} calls</span>
            <span>{formatCurrency(scan.llm_cost_usd)}</span>
          </div>
        </div>

        {compact ? null : <div className="scan-target">{scan.target_url}</div>}
        <div className="scan-meta-row">
          <span>{formatDateTime(scan.created_at)}</span>
          <span>{String(scan.run_id).slice(0, 8)}</span>
        </div>
      </button>
    </article>
  );
}

function groupScansByTarget(scans) {
  const map = new Map();
  for (const scan of scans) {
    const key = scan.target_url || "(unknown)";
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(scan);
  }
  const groups = [];
  for (const [targetUrl, runs] of map) {
    groups.push({ targetUrl, runs, latest: runs[0] });
  }
  return groups;
}

function ScanGroup({ group, selectedRunId, onSelect, now, expandedTarget, onToggle }) {
  const isExpanded = expandedTarget === group.targetUrl;
  const hasSelected = group.runs.some((s) => s.run_id === selectedRunId);
  const latestStatus = getEffectiveStatus(group.latest, now);

  const runningCount = group.runs.filter((s) => s.status === "running").length;
  const finishedCount = group.runs.filter((s) => s.status === "finished" || s.status === "completed").length;
  const totalCost = group.runs.reduce((sum, s) => sum + Number(s.llm_cost_usd || 0), 0);

  return (
    <div className={`scan-group ${hasSelected ? "scan-group-active" : ""}`}>
      <button type="button" className="scan-group-header" onClick={() => onToggle(isExpanded ? null : group.targetUrl)}>
        <div className="scan-group-top">
          <span className={`status-pill tone-${latestStatus.tone}`}>{latestStatus.label}</span>
          <span className="scan-group-count">{group.runs.length}회</span>
          <span className="scan-group-expand">{isExpanded ? "▲" : "▼"}</span>
        </div>
        <div className="scan-group-url">{group.targetUrl}</div>
        <div className="scan-group-meta">
          {runningCount > 0 ? <span className="scan-group-badge tone-running">{runningCount} 실행 중</span> : null}
          {finishedCount > 0 ? <span className="scan-group-badge tone-finished">{finishedCount} 완료</span> : null}
          <span>{formatCurrency(totalCost)}</span>
        </div>
      </button>

      {isExpanded ? (
        <div className="scan-group-runs">
          {group.runs.map((scan) => (
            <ScanCard key={scan.run_id} scan={scan} selected={scan.run_id === selectedRunId} onSelect={onSelect} now={now} compact />
          ))}
        </div>
      ) : !isExpanded && !hasSelected ? (
        <button type="button" className="scan-group-quick" onClick={() => onSelect(group.latest.run_id)}>
          최신 결과 보기
        </button>
      ) : null}
    </div>
  );
}

function ResultsView({
  snapshot,
  now,
  onRefresh,
  onOpenFindings,
  onOpenCandidates,
  onOpenRunDetails,
  onOpenLlmTrace,
  onOpenDiscoveryTree,
  onOpenApiSpecs,
  onStop,
  stopLoading,
}) {
  if (!snapshot?.scan) {
    return <EmptyState title="실행을 선택하세요" body="왼쪽 목록에서 스캔을 선택하면 실시간 상태를 볼 수 있습니다." className="empty-hero" />;
  }

  const scan = snapshot.scan;
  const statusMeta = getEffectiveStatus(scan, now);
  const stale = statusMeta === STATUS_META.stale;
  const candidateCount = snapshot.candidate_count ?? snapshot.candidates?.length ?? 0;
  const requestCount = snapshot.request_catalog_count ?? 0;

  return (
    <>
      <section className="hero-card">
        <div className="hero-topline">
          <div>
            <h1>{scan.target_url}</h1>
          </div>

          <div className="hero-badges">
            <StatusPill scan={scan} now={now} />
            <span className="scan-engine">{getScanEngine(scan)}</span>
          </div>
        </div>

        <div className="hero-actions" style={{ marginTop: 18 }}>
          <button type="button" className="icon-button" title="스냅샷 새로고침" onClick={onRefresh}>↻</button>
          <button type="button" className="ghost-button" onClick={onOpenRunDetails}>자세히 보기</button>
          <button type="button" className="ghost-button" onClick={onOpenLlmTrace}>LLM 기록 보기</button>
          {scan.status === "running" ? (
            <button type="button" className="ghost-button danger-button" disabled={stopLoading} onClick={onStop}>
              {stopLoading ? "중지 요청 중..." : "중지"}
            </button>
          ) : null}
        </div>
      </section>

      <div className="stats-grid">
        <StatCard
          label="취약점"
          value={formatCount(snapshot.summary?.total_findings || 0)}
          helper="확정된 보안 이슈"
          tone="danger"
          onClick={onOpenFindings}
          actionLabel="목록 열기"
        />
        <StatCard
          label="가설"
          value={formatCount(candidateCount)}
          helper="저장된 분석 후보"
          tone="accent"
          onClick={onOpenCandidates}
          actionLabel="목록 열기"
        />
        <StatCard label="요청" value={formatCount(requestCount)} helper="수집된 엔드포인트" tone="neutral" />
        <StatCard label="LLM 호출" value={formatCount(scan.llm_calls_count)} helper="모델 상호작용 수" tone="accent" />
        <StatCard
          label="사용량"
          value={formatCompactCount(scan.llm_tokens_used)}
          helper={`${formatCount(scan.llm_tokens_used)} tokens | ${formatCurrency(scan.llm_cost_usd)}`}
          tone="warning"
        />
        {scan.mode === "discovery" ? (
          <StatCard
            label="탐색 트리"
            value="Tree"
            helper="Discovery 탐색 과정"
            tone="accent"
            onClick={onOpenDiscoveryTree}
            actionLabel="트리 보기"
          />
        ) : null}
        <StatCard
          label="API 명세"
          value="Spec"
          helper="이 사이트의 누적 endpoint 명세 (host KB)"
          tone="neutral"
          onClick={onOpenApiSpecs}
          actionLabel="명세 보기"
        />
      </div>

      <SectionCard title="상태" kicker="실행 메모">
        <div className="status-grid">
          <div><span>현재 상태</span><strong>{statusMeta.label}</strong></div>
          <div><span>생성 시각</span><strong>{formatDateTime(scan.created_at)}</strong></div>
          <div><span>최근 백엔드 활동</span><strong>{formatAgo(scan.updated_at, now)}</strong></div>
          <div><span>런타임</span><strong>{formatRuntime(scan, now)}</strong></div>
        </div>

        {stale ? <div className="callout callout-warn">최근 백엔드 활동이 없어 실제로는 멈춘 실행일 수 있습니다.</div> : null}
        {scan.status === "stopped" ? <div className="callout callout-neutral">사용자 요청으로 스캔이 중지되었습니다.</div> : null}

        {scan.error_log ? (
          <div className="failure-panel">
            <strong>실패 로그</strong>
            <pre className="failure-log">{scan.error_log}</pre>
          </div>
        ) : null}
      </SectionCard>
    </>
  );
}

const NODE_TYPE_META = {
  target: { icon: "\u25C9", label: "\ud0c0\uac9f" },
  endpoint: { icon: "\u2192", label: "\uc5d4\ub4dc\ud3ec\uc778\ud2b8" },
  vuln: { icon: "\u26a0", label: "\ucde8\uc57d\uc810" },
  clue: { icon: "\u2727", label: "\ub2e8\uc11c" },
  exploit_step: { icon: "\u2191", label: "\uc775\uc2a4\ud50c\ub85c\uc787" },
  flag: { icon: "\u2691", label: "\ud50c\ub798\uadf8" },
  dead_end: { icon: "\u00d7", label: "\ub9c9\ub2e4\ub978 \uacf5" },
};

const NODE_STATUS_LABEL = {
  pending: "\ub300\uae30",
  exploring: "\ud0d0\uc0c9 \uc911",
  explored: "\ud0d0\uc0c9 \uc644\ub8cc",
  dead_end: "\ub9c9\ub2e4\ub978 \uacf5",
  confirmed: "\ud655\uc815",
};

function buildTreeFromFlat(flatNodes) {
  const map = new Map();
  const roots = [];
  for (const n of flatNodes) {
    map.set(n.node_id, { ...n, children: [] });
  }
  for (const n of flatNodes) {
    const node = map.get(n.node_id);
    if (n.parent && map.has(n.parent)) {
      map.get(n.parent).children.push(node);
    } else {
      roots.push(node);
    }
  }
  return roots;
}

const CARD_W = 240;
const CARD_H = 64;
const GAP_X = 280;
const GAP_Y = 90;
const ZOOM_MIN = 0.25;
const ZOOM_MAX = 2.5;

function layoutTree(roots) {
  const positions = new Map();
  let nextY = 0;
  function lay(node, depth) {
    const childYs = [];
    for (const child of node.children || []) {
      lay(child, depth + 1);
      childYs.push(positions.get(child.node_id).y);
    }
    const y = childYs.length ? (childYs[0] + childYs[childYs.length - 1]) / 2 : nextY++ * GAP_Y;
    positions.set(node.node_id, { x: depth * GAP_X, y });
  }
  for (const root of roots) lay(root, 0);
  return positions;
}

function collectEdges(roots) {
  const edges = [];
  function walk(node) {
    for (const child of node.children || []) {
      edges.push({ from: node.node_id, to: child.node_id });
      walk(child);
    }
  }
  for (const r of roots) walk(r);
  return edges;
}

function CanvasEdges({ edges, positions }) {
  const paths = [];
  for (const { from, to } of edges) {
    const a = positions.get(from);
    const b = positions.get(to);
    if (!a || !b) continue;
    const x1 = a.x + CARD_W;
    const y1 = a.y + CARD_H / 2;
    const x2 = b.x;
    const y2 = b.y + CARD_H / 2;
    const cx = Math.min(80, Math.abs(x2 - x1) * 0.4);
    paths.push(<path key={`${from}-${to}`} d={`M${x1},${y1} C${x1 + cx},${y1} ${x2 - cx},${y2} ${x2},${y2}`} />);
  }
  return (
    <svg className="canvas-edges">
      <g>{paths}</g>
    </svg>
  );
}

function CanvasNode({ node, x, y, selected, onSelect }) {
  const meta = NODE_TYPE_META[node.node_type] || NODE_TYPE_META.clue;
  const statusLabel = NODE_STATUS_LABEL[node.status] || node.status;
  const isSelected = selected === node.node_id;

  return (
    <div
      className={`canvas-node node-type-${node.node_type} ${isSelected ? "canvas-node-selected" : ""}`}
      style={{ left: x, top: y }}
      onClick={(e) => { e.stopPropagation(); onSelect(isSelected ? null : node.node_id); }}
    >
      <div className="node-head">
        <span className="node-icon">{meta.icon}</span>
        <span className="node-type-label">{meta.label}</span>
        {node.vuln_type ? <span className="node-vuln-badge">{node.vuln_type}</span> : null}
        <span className={`node-status-pill node-status-${node.status}`}>{statusLabel}</span>
      </div>
      <div className="node-summary">{node.summary}</div>
    </div>
  );
}

function NodeDetailPanel({ node, allNodes, requests = [], candidates = [], findings = [], endpointSpecs = [], onClose }) {
  if (!node) return null;

  const meta = NODE_TYPE_META[node.node_type] || NODE_TYPE_META.clue;
  const statusLabel = NODE_STATUS_LABEL[node.status] || node.status;

  const chain = useMemo(() => {
    const path = [];
    let current = node;
    const nodeMap = new Map(allNodes.map((n) => [n.node_id, n]));
    while (current) {
      path.unshift(current);
      current = current.parent ? nodeMap.get(current.parent) : null;
    }
    return path;
  }, [node, allNodes]);

  const children = useMemo(
    () => allNodes.filter((n) => n.parent === node.node_id),
    [node, allNodes],
  );

  const ctx = node.context || {};
  const contextEntries = Object.entries(ctx).filter(([k]) => k !== "raw");

  // ── 노드 ↔ candidate / finding / request 매칭 ──
  // 우선 features.discovery_node_id 직매칭, 없으면 endpoint+vuln_type 매칭
  const nodeId = node.node_id;
  const epNorm = (node.endpoint || "").split("?")[0].replace(/\/+$/, "") || "/";

  const linkedCandidates = useMemo(() => {
    return candidates.filter((c) => {
      const feat = c.features || {};
      if (feat.discovery_node_id === nodeId) return true;
      const cep = (feat.endpoint || (c.request && c.request.endpoint) || "").split("?")[0].replace(/\/+$/, "") || "/";
      return cep === epNorm && (!node.vuln_type || c.vuln_type === node.vuln_type);
    });
  }, [candidates, nodeId, epNorm, node.vuln_type]);

  const linkedCandIds = new Set(linkedCandidates.map((c) => c.cand_id));
  const linkedFindings = useMemo(
    () => findings.filter((f) => linkedCandIds.has(f.candidate)),
    [findings, linkedCandidates],
  );

  const linkedRequests = useMemo(() => {
    if (!node.endpoint) return [];
    return requests.filter((r) => {
      const rep = (r.endpoint || "").split("?")[0].replace(/\/+$/, "") || "/";
      return rep === epNorm;
    }).slice(0, 20);
  }, [requests, node.endpoint, epNorm]);

  // EndpointSpec — host KB 자산. 같은 endpoint 의 명세 (params/sinks/auth 등).
  const linkedSpecs = useMemo(() => {
    if (!node.endpoint || node.node_type === "target") return [];
    return endpointSpecs.filter((s) => {
      const sep = (s.endpoint || "").split("?")[0].replace(/\/+$/, "") || "/";
      return sep === epNorm;
    });
  }, [endpointSpecs, node.endpoint, node.node_type, epNorm]);

  return (
    <div className="node-panel" onClick={(e) => e.stopPropagation()}>
      <div className="node-panel-head">
        <div className="node-panel-title">
          <span className="node-icon">{meta.icon}</span>
          <span className={`node-type-label node-type-${node.node_type}`}>{meta.label}</span>
          <span className={`node-status-pill node-status-${node.status}`}>{statusLabel}</span>
        </div>
        <button type="button" className="ghost-button" onClick={onClose}>닫기</button>
      </div>

      <div className="node-panel-summary">{node.summary}</div>

      <div className="node-panel-grid">
        {node.endpoint ? <div><span>Endpoint</span><strong>{node.endpoint}</strong></div> : null}
        {node.vuln_type ? <div><span>취약점 유형</span><strong>{node.vuln_type}</strong></div> : null}
        <div><span>깊이</span><strong>{node.depth}</strong></div>
        <div><span>자식 노드</span><strong>{node.children_count}</strong></div>
        {node.worker_id ? <div><span>Worker</span><strong>{node.worker_id}</strong></div> : null}
        <div><span>생성</span><strong>{formatDateTime(node.created_at)}</strong></div>
        {node.explored_at ? <div><span>탐색</span><strong>{formatDateTime(node.explored_at)}</strong></div> : null}
      </div>

      {chain.length > 1 ? (
        <div className="node-panel-section">
          <div className="mini-title">공격 경로</div>
          <div className="node-chain">
            {chain.map((c, i) => {
              const m = NODE_TYPE_META[c.node_type] || NODE_TYPE_META.clue;
              return (
                <div key={c.node_id} className={`node-chain-step ${c.node_id === node.node_id ? "current" : ""}`}>
                  <span className="node-chain-icon">{m.icon}</span>
                  <span className="node-chain-text">{c.summary.slice(0, 80)}{c.summary.length > 80 ? "..." : ""}</span>
                  {i < chain.length - 1 ? <span className="node-chain-arrow">→</span> : null}
                </div>
              );
            })}
          </div>
        </div>
      ) : null}

      {contextEntries.length > 0 ? (
        <div className="node-panel-section">
          <div className="mini-title">Context</div>
          <pre className="node-panel-context">{JSON.stringify(ctx, null, 2)}</pre>
        </div>
      ) : null}

      {children.length > 0 ? (
        <div className="node-panel-section">
          <div className="mini-title">자식 노드 ({children.length})</div>
          <div className="node-children-list">
            {children.map((c) => {
              const cm = NODE_TYPE_META[c.node_type] || NODE_TYPE_META.clue;
              const sl = NODE_STATUS_LABEL[c.status] || c.status;
              return (
                <div key={c.node_id} className="node-child-row">
                  <span className="node-icon">{cm.icon}</span>
                  <span className="node-child-summary">{c.summary.slice(0, 60)}</span>
                  <span className={`node-status-pill node-status-${c.status}`}>{sl}</span>
                </div>
              );
            })}
          </div>
        </div>
      ) : null}

      {linkedSpecs.length > 0 ? (
        <div className="node-panel-section">
          <div className="mini-title">📋 API 명세 ({linkedSpecs.length})</div>
          <div className="node-children-list">
            {linkedSpecs.map((s) => (
              <div key={s.spec_id} className="node-child-row" style={{ flexDirection: "column", alignItems: "stretch", gap: 4 }}>
                <div>
                  <strong>{s.method}</strong> {s.endpoint}
                  {s.auth_required ? <span style={{ marginLeft: 6, opacity: 0.7 }}>🔒 auth</span> : null}
                  <span style={{ marginLeft: 8, opacity: 0.6, fontSize: "0.85em" }}>seen {s.times_seen}× </span>
                </div>
                {s.suspected_vuln_types && s.suspected_vuln_types.length > 0 ? (
                  <div style={{ fontSize: "0.85em" }}>
                    <span style={{ opacity: 0.7 }}>의심 vuln: </span>
                    {s.suspected_vuln_types.map((vt) => (
                      <span key={vt} className="node-status-pill node-status-pending" style={{ marginRight: 4 }}>{vt}</span>
                    ))}
                  </div>
                ) : null}
                {s.sink_hints && s.sink_hints.length > 0 ? (
                  <div style={{ fontSize: "0.85em", opacity: 0.8 }}>
                    sink: {s.sink_hints.join(", ")}
                  </div>
                ) : null}
                {s.params_schema && Object.keys(s.params_schema).length > 0 ? (
                  <div style={{ fontSize: "0.8em", opacity: 0.7 }}>
                    params: {Object.keys(s.params_schema).join(", ")}
                  </div>
                ) : null}
                {s.notes ? (
                  <div style={{ fontSize: "0.8em", opacity: 0.6, fontStyle: "italic" }}>{s.notes.slice(0, 200)}</div>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {linkedFindings.length > 0 ? (
        <div className="node-panel-section">
          <div className="mini-title">취약점 ({linkedFindings.length})</div>
          <div className="node-children-list">
            {linkedFindings.map((f) => (
              <div key={f.finding_id} className="node-child-row">
                <span className="node-icon">⚠</span>
                <span className="node-child-summary">
                  <strong>[{(f.severity || "?").toUpperCase()}]</strong> {f.title || "(제목 없음)"}
                  {f.summary ? <div style={{ opacity: 0.7, fontSize: "0.85em", marginTop: 2 }}>{f.summary.slice(0, 200)}</div> : null}
                </span>
                <span className={`node-status-pill node-status-confirmed`}>{f.vuln_type}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {linkedCandidates.length > 0 ? (
        <div className="node-panel-section">
          <div className="mini-title">후보 ({linkedCandidates.length})</div>
          <div className="node-children-list">
            {linkedCandidates.slice(0, 10).map((c) => (
              <div key={c.cand_id} className="node-child-row">
                <span className="node-icon">◆</span>
                <span className="node-child-summary">
                  {c.vuln_type} — {(c.hypothesis || "").slice(0, 80)}
                  {c.priority_score ? <span style={{ opacity: 0.6, marginLeft: 6 }}>p={Number(c.priority_score).toFixed(2)}</span> : null}
                </span>
                <span className={`node-status-pill node-status-${c.status === "confirmed" ? "confirmed" : c.status === "false_positive" || c.status === "dismissed" ? "dead_end" : "pending"}`}>
                  {c.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {linkedRequests.length > 0 ? (
        <div className="node-panel-section">
          <div className="mini-title">관련 요청 ({linkedRequests.length})</div>
          <div className="node-children-list">
            {linkedRequests.slice(0, 10).map((r) => (
              <div key={r.req_id || r.request_id} className="node-child-row">
                <span className="node-icon">{r.method === "GET" ? "→" : r.method === "POST" ? "↑" : "·"}</span>
                <span className="node-child-summary">
                  <strong>{r.method}</strong> {r.endpoint}
                  {r.params && Object.keys(r.params).length > 0 ? (
                    <div style={{ opacity: 0.7, fontSize: "0.85em", marginTop: 2 }}>
                      params: {Object.keys(r.params).join(", ").slice(0, 120)}
                    </div>
                  ) : null}
                </span>
                <span className="node-status-pill node-status-explored">{r.source || "?"}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function flattenTree(roots) {
  const out = [];
  function walk(node) { out.push(node); for (const c of node.children || []) walk(c); }
  for (const r of roots) walk(r);
  return out;
}

// REST endpoint path 를 패턴으로 정규화 — 숫자/UUID/hex 식별자를 placeholder 로.
// `/api/users/123` → `/api/users/{id}`, `/items/3f9-uuid-...` → `/items/{uuid}`.
function normalizeEndpointPath(p) {
  if (!p) return p;
  const [pathOnly, query] = p.split("?", 2);
  const segs = pathOnly.split("/").map((seg) => {
    if (!seg) return seg;
    if (/^\d+$/.test(seg)) return "{id}";
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return "{uuid}";
    if (/^[0-9a-f]{16,}$/i.test(seg)) return "{hash}";
    return seg;
  });
  return segs.join("/") + (query ? `?${query}` : "");
}

function EndpointSpecModal({ runId, targetUrl, onClose }) {
  const [data, setData] = useState({ host: "", count: 0, specs: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [vulnFilter, setVulnFilter] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  const [expandedGroups, setExpandedGroups] = useState(new Set());

  async function fetchSpecs() {
    setLoading(true);
    try {
      const d = await apiGet(`/api/scan-runs/${runId}/endpoint-specs/`);
      setData(d || { host: "", count: 0, specs: [] });
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { fetchSpecs(); }, [runId]);

  const allVulnTypes = useMemo(() => {
    const s = new Set();
    for (const spec of data.specs || []) {
      for (const vt of spec.suspected_vuln_types || []) s.add(vt);
    }
    return Array.from(s).sort();
  }, [data]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return (data.specs || []).filter((s) => {
      if (vulnFilter && !(s.suspected_vuln_types || []).includes(vulnFilter)) return false;
      if (!q) return true;
      const hay = `${s.method} ${s.endpoint} ${(s.suspected_vuln_types || []).join(" ")} ${(s.sink_hints || []).join(" ")} ${s.notes || ""}`.toLowerCase();
      return hay.includes(q);
    });
  }, [data, filter, vulnFilter]);

  // (method, normalized_path) 로 그룹화 — `/api/login/1`, `/api/login/2` → `/api/login/{id}`.
  // 그룹 내 1개뿐이면 single row 그대로, 2개+ 면 accordion (요약 행 + click 시 멤버 펼침).
  const groups = useMemo(() => {
    const map = new Map();
    for (const s of filtered) {
      const norm = normalizeEndpointPath(s.endpoint);
      const key = `${s.method} ${norm}`;
      if (!map.has(key)) {
        map.set(key, { key, method: s.method, normPath: norm, members: [] });
      }
      map.get(key).members.push(s);
    }
    // 각 그룹 derive
    const arr = Array.from(map.values()).map((g) => {
      const vt = new Set();
      const sinks = new Set();
      let auth = false, seen = 0;
      for (const m of g.members) {
        for (const v of m.suspected_vuln_types || []) vt.add(v);
        for (const k of m.sink_hints || []) sinks.add(k);
        if (m.auth_required) auth = true;
        seen += m.times_seen || 0;
      }
      return {
        ...g,
        size: g.members.length,
        union_vuln_types: Array.from(vt).sort(),
        union_sinks: Array.from(sinks).sort(),
        any_auth: auth,
        total_seen: seen,
      };
    });
    // 멤버가 많은 순, 그 다음 path 알파벳
    arr.sort((a, b) => (b.size - a.size) || a.normPath.localeCompare(b.normPath));
    return arr;
  }, [filtered]);

  const selected = useMemo(
    () => (data.specs || []).find((s) => s.spec_id === selectedId),
    [data, selectedId],
  );

  function toggleGroup(key) {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  const stopProp = (e) => e.stopPropagation();

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-card modal-card-wide"
        onClick={stopProp}
        style={{
          maxWidth: 1200,
          width: "min(1200px, 100%)",
          padding: 0,
          display: "flex",
          flexDirection: "column",
          maxHeight: "85vh",
          overflow: "hidden",
        }}
      >
        <div className="modal-head" style={{ padding: "16px 20px", borderBottom: "1px solid #e6ebf2" }}>
          <div>
            <h2 style={{ margin: 0 }}>📋 API 명세 (Endpoint Spec KB)</h2>
            <div style={{ marginTop: 4, opacity: 0.7, fontSize: "0.85em" }}>
              host: <code>{data.host || "-"}</code> · {data.count} specs
              {targetUrl ? <span style={{ marginLeft: 8 }}>· target: <code>{targetUrl}</code></span> : null}
            </div>
          </div>
          <div className="modal-actions">
            <button type="button" className="icon-button" title="새로고침" onClick={fetchSpecs}>↻</button>
            <button type="button" className="ghost-button" onClick={onClose}>닫기</button>
          </div>
        </div>

        <div style={{
          padding: "10px 20px", display: "flex", gap: 8, alignItems: "center",
          flexWrap: "wrap", background: "#f7f9fc", borderBottom: "1px solid #e6ebf2",
        }}>
          <input
            type="text"
            placeholder="endpoint / sink / notes 검색…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ flex: 1, minWidth: 200, padding: "7px 12px", border: "1px solid #ccd5e0", borderRadius: 4, background: "#fff" }}
          />
          <select
            value={vulnFilter}
            onChange={(e) => setVulnFilter(e.target.value)}
            style={{ padding: "7px 10px", border: "1px solid #ccd5e0", borderRadius: 4, background: "#fff" }}
          >
            <option value="">all vuln_types</option>
            {allVulnTypes.map((vt) => (
              <option key={vt} value={vt}>{vt}</option>
            ))}
          </select>
          <span style={{ opacity: 0.7, fontSize: "0.85em", color: "#5a6573" }}>{filtered.length} / {data.count}</span>
        </div>

        {error ? <div className="callout callout-error">{error}</div> : null}
        {loading && !data.specs?.length ? <div className="callout callout-neutral">명세를 불러오는 중...</div> : null}

        {!loading && data.count === 0 ? (
          <div className="callout callout-neutral" style={{ margin: 14 }}>
            이 host 에 누적된 endpoint 명세가 아직 없습니다. EntryPoint sub-agent 가
            <code> record_endpoint_spec</code> 를 호출하거나, 취약점 confirm 시 안전망이
            자동으로 명세를 만듭니다. discovery scan 을 한 번 더 돌리거나 같은 host
            를 자동 resume 하면 누적이 시작됩니다.
          </div>
        ) : null}

        <div style={{ display: "flex", flex: 1, overflow: "hidden", background: "#fff" }}>
          <div style={{ flex: 1, overflowY: "auto", borderRight: "1px solid #e6ebf2" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9em", background: "#fff" }}>
              <thead style={{ position: "sticky", top: 0, background: "#eef2f7", zIndex: 1 }}>
                <tr>
                  <th style={{ textAlign: "left", padding: "8px 12px", borderBottom: "2px solid #d3dae4", width: 70, color: "#1f2a3a" }}>method</th>
                  <th style={{ textAlign: "left", padding: "8px 12px", borderBottom: "2px solid #d3dae4", color: "#1f2a3a" }}>endpoint</th>
                  <th style={{ textAlign: "left", padding: "8px 12px", borderBottom: "2px solid #d3dae4", color: "#1f2a3a" }}>의심 vuln</th>
                  <th style={{ textAlign: "right", padding: "8px 12px", borderBottom: "2px solid #d3dae4", width: 70, color: "#1f2a3a" }}>seen</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => {
                  // 멤버 1개뿐 — 그룹 행 없이 바로 single row.
                  if (g.size === 1) {
                    const s = g.members[0];
                    return (
                      <tr
                        key={s.spec_id}
                        onClick={() => setSelectedId(s.spec_id)}
                        style={{
                          cursor: "pointer",
                          background: selectedId === s.spec_id ? "#dbe7fb" : "#fff",
                          borderBottom: "1px solid #eef2f7",
                          color: "#1f2a3a",
                        }}
                      >
                        <td style={{ padding: "8px 12px" }}><strong>{s.method}</strong></td>
                        <td style={{ padding: "8px 12px" }}>
                          {s.endpoint}
                          {s.auth_required ? <span style={{ marginLeft: 6, opacity: 0.75 }}>🔒</span> : null}
                        </td>
                        <td style={{ padding: "8px 12px" }}>
                          {(s.suspected_vuln_types || []).map((vt) => (
                            <span key={vt} className="node-status-pill node-status-pending" style={{ marginRight: 3, fontSize: "0.8em" }}>{vt}</span>
                          ))}
                        </td>
                        <td style={{ padding: "8px 12px", textAlign: "right", opacity: 0.75 }}>{s.times_seen}×</td>
                      </tr>
                    );
                  }
                  // 멤버 2개+ — 그룹 행(요약) + 펼침 시 멤버 행들.
                  const isOpen = expandedGroups.has(g.key);
                  return (
                    <Fragment key={g.key}>
                      <tr
                        onClick={() => toggleGroup(g.key)}
                        style={{
                          cursor: "pointer",
                          background: isOpen ? "#eef4fc" : "#f7f9fc",
                          borderBottom: "1px solid #d3dae4",
                          color: "#1f2a3a",
                          fontWeight: 500,
                        }}
                      >
                        <td style={{ padding: "8px 12px" }}>
                          <span style={{ marginRight: 6, opacity: 0.7 }}>{isOpen ? "▼" : "▶"}</span>
                          <strong>{g.method}</strong>
                        </td>
                        <td style={{ padding: "8px 12px" }}>
                          {g.normPath}
                          {g.any_auth ? <span style={{ marginLeft: 6, opacity: 0.75 }}>🔒</span> : null}
                          <span style={{ marginLeft: 8, opacity: 0.65, fontWeight: 400, fontSize: "0.85em" }}>
                            ({g.size} variants)
                          </span>
                        </td>
                        <td style={{ padding: "8px 12px" }}>
                          {g.union_vuln_types.map((vt) => (
                            <span key={vt} className="node-status-pill node-status-pending" style={{ marginRight: 3, fontSize: "0.8em" }}>{vt}</span>
                          ))}
                        </td>
                        <td style={{ padding: "8px 12px", textAlign: "right", opacity: 0.75 }}>{g.total_seen}×</td>
                      </tr>
                      {isOpen ? g.members.map((s) => (
                        <tr
                          key={s.spec_id}
                          onClick={(e) => { e.stopPropagation(); setSelectedId(s.spec_id); }}
                          style={{
                            cursor: "pointer",
                            background: selectedId === s.spec_id ? "#dbe7fb" : "#fff",
                            borderBottom: "1px solid #eef2f7",
                            color: "#1f2a3a",
                          }}
                        >
                          <td style={{ padding: "6px 12px 6px 28px", opacity: 0.75 }}>{s.method}</td>
                          <td style={{ padding: "6px 12px 6px 28px" }}>
                            <span style={{ opacity: 0.6, marginRight: 4 }}>└</span>
                            {s.endpoint}
                            {s.auth_required ? <span style={{ marginLeft: 6, opacity: 0.75 }}>🔒</span> : null}
                          </td>
                          <td style={{ padding: "6px 12px" }}>
                            {(s.suspected_vuln_types || []).map((vt) => (
                              <span key={vt} className="node-status-pill node-status-pending" style={{ marginRight: 3, fontSize: "0.8em" }}>{vt}</span>
                            ))}
                          </td>
                          <td style={{ padding: "6px 12px", textAlign: "right", opacity: 0.75 }}>{s.times_seen}×</td>
                        </tr>
                      )) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          {selected ? (
            <div style={{ width: 440, padding: 18, overflowY: "auto", background: "#f7f9fc", color: "#1f2a3a" }}>
              <div style={{ marginBottom: 8 }}>
                <strong style={{ fontSize: "1.1em" }}>{selected.method} {selected.endpoint}</strong>
                {selected.auth_required ? <span style={{ marginLeft: 8 }}>🔒 auth</span> : null}
              </div>
              <div style={{ opacity: 0.7, fontSize: "0.85em", marginBottom: 12 }}>
                seen {selected.times_seen}×{selected.last_seen_at ? ` · last ${selected.last_seen_at.slice(0, 19).replace("T", " ")}` : ""}
              </div>

              {selected.suspected_vuln_types?.length ? (
                <div className="node-panel-section">
                  <div className="mini-title">의심 vuln_types</div>
                  <div>
                    {selected.suspected_vuln_types.map((vt) => (
                      <span key={vt} className="node-status-pill node-status-pending" style={{ marginRight: 4 }}>{vt}</span>
                    ))}
                  </div>
                </div>
              ) : null}

              {selected.sink_hints?.length ? (
                <div className="node-panel-section">
                  <div className="mini-title">Sink hints</div>
                  <pre className="node-panel-context">{selected.sink_hints.join("\n")}</pre>
                </div>
              ) : null}

              {selected.params_schema && Object.keys(selected.params_schema).length ? (
                <div className="node-panel-section">
                  <div className="mini-title">Params schema</div>
                  <pre className="node-panel-context">{JSON.stringify(selected.params_schema, null, 2)}</pre>
                </div>
              ) : null}

              {selected.headers_required?.length ? (
                <div className="node-panel-section">
                  <div className="mini-title">Headers required</div>
                  <pre className="node-panel-context">{selected.headers_required.join("\n")}</pre>
                </div>
              ) : null}

              {selected.response_shape && Object.keys(selected.response_shape).length ? (
                <div className="node-panel-section">
                  <div className="mini-title">Response shape</div>
                  <pre className="node-panel-context">{JSON.stringify(selected.response_shape, null, 2)}</pre>
                </div>
              ) : null}

              {selected.notes ? (
                <div className="node-panel-section">
                  <div className="mini-title">Notes</div>
                  <div style={{ whiteSpace: "pre-wrap", fontSize: "0.9em", opacity: 0.85 }}>{selected.notes}</div>
                </div>
              ) : null}
            </div>
          ) : (
            <div style={{ width: 440, padding: 24, fontSize: "0.9em", background: "#f7f9fc", color: "#5a6573" }}>
              ← 좌측 표에서 endpoint 를 선택하면 상세 명세 (params / sinks / response shape / notes) 가 보입니다.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


function DiscoveryTreeModal({ runId, scanStatus, onClose }) {
  const [nodes, setNodes] = useState([]);
  const [requests, setRequests] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [findings, setFindings] = useState([]);
  const [endpointSpecs, setEndpointSpecs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState(null);

  const [pan, setPan] = useState({ x: 40, y: 40 });
  const [zoom, setZoom] = useState(1);
  const dragRef = useRef(null);
  const wasDragRef = useRef(false);
  const vpRef = useRef(null);

  async function fetchTree() {
    setLoading(true);
    try {
      // 5개 fetch 병렬 — 노드 detail panel 이 candidate/finding/request/spec 도
      // 보여주려면 다 필요. EndpointSpec 은 host KB 자산 (scan 외부에 누적됨).
      const [treeData, reqData, candData, findData, specData] = await Promise.all([
        apiGet(`/api/scan-runs/${runId}/discovery-tree/`),
        apiGet(`/api/scan-runs/${runId}/request-catalog/?page_size=200`).catch(() => ({})),
        apiGet(`/api/candidates/list/?run_id=${runId}&page_size=200`).catch(() => ({})),
        apiGet(`/api/findings/?run_id=${runId}&page_size=200`).catch(() => ({})),
        apiGet(`/api/scan-runs/${runId}/endpoint-specs/`).catch(() => ({})),
      ]);
      setNodes(Array.isArray(treeData) ? treeData : []);
      setRequests(normalizePaginatedList(reqData));
      setCandidates(normalizePaginatedList(candData));
      setFindings(normalizePaginatedList(findData));
      setEndpointSpecs(Array.isArray(specData?.specs) ? specData.specs : []);
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchTree();
    if (scanStatus === "running") {
      const timer = window.setInterval(fetchTree, 15000);
      return () => window.clearInterval(timer);
    }
  }, [runId, scanStatus]);

  const roots = useMemo(() => buildTreeFromFlat(nodes), [nodes]);
  const positions = useMemo(() => layoutTree(roots), [roots]);
  const edges = useMemo(() => collectEdges(roots), [roots]);
  const allNodes = useMemo(() => flattenTree(roots), [roots]);

  const stats = useMemo(() => {
    const s = { total: nodes.length, confirmed: 0, dead_end: 0, pending: 0, exploring: 0, explored: 0, maxDepth: 0 };
    for (const n of nodes) {
      if (n.status === "confirmed") s.confirmed++;
      else if (n.status === "dead_end") s.dead_end++;
      else if (n.status === "pending") s.pending++;
      else if (n.status === "exploring") s.exploring++;
      else s.explored++;
      if (n.depth > s.maxDepth) s.maxDepth = n.depth;
    }
    return s;
  }, [nodes]);

  const barSegments = useMemo(() => {
    if (!stats.total) return [];
    return [
      { key: "confirmed", count: stats.confirmed, label: "\ud655\uc815" },
      { key: "explored", count: stats.explored, label: "\ud0d0\uc0c9 \uc644\ub8cc" },
      { key: "exploring", count: stats.exploring, label: "\ud0d0\uc0c9 \uc911" },
      { key: "pending", count: stats.pending, label: "\ub300\uae30" },
      { key: "dead_end", count: stats.dead_end, label: "\ub9c9\ub2e4\ub978 \uacf5" },
    ].filter((s) => s.count > 0);
  }, [stats]);

  // 이전 scan 이어받기 정보 — root 노드의 context.previous_scan + 트리 안 [seeded]/[re-verify]/
  // [prev dead_end]/[prev clue|exploit_step] prefix 카운트.
  const resumeInfo = useMemo(() => {
    const root = nodes.find((n) => n.depth === 0);
    const prev = root?.context?.previous_scan;
    if (!prev) return null;
    let endpoints = 0, vulns = 0, dead = 0, clues = 0;
    for (const n of nodes) {
      const s = n.summary || "";
      if (s.startsWith("[seeded]")) endpoints++;
      else if (s.startsWith("[re-verify]")) vulns++;
      else if (s.startsWith("[prev dead_end]")) dead++;
      else if (s.startsWith("[prev clue]") || s.startsWith("[prev exploit_step]")) clues++;
    }
    return {
      prev_run_id: prev.prev_run_id || "",
      endpoints, vulns, dead, clues,
      total: endpoints + vulns + dead + clues,
    };
  }, [nodes]);

  const handleWheel = useCallback((e) => {
    e.preventDefault();
    const vp = vpRef.current;
    if (!vp) return;
    const rect = vp.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const factor = e.deltaY < 0 ? 1.12 : 0.89;
    setZoom((prev) => {
      const next = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, prev * factor));
      const ratio = next / prev;
      setPan((p) => ({ x: mx - ratio * (mx - p.x), y: my - ratio * (my - p.y) }));
      return next;
    });
  }, []);

  useEffect(() => {
    const vp = vpRef.current;
    if (!vp) return;
    vp.addEventListener("wheel", handleWheel, { passive: false });
    return () => vp.removeEventListener("wheel", handleWheel);
  }, [handleWheel]);

  const DRAG_THRESHOLD = 4;

  const onPointerDown = useCallback((e) => {
    if (e.button !== 0) return;
    dragRef.current = { startX: e.clientX, startY: e.clientY, startPan: { ...pan }, dragging: false };
  }, [pan]);

  const onPointerMove = useCallback((e) => {
    if (!dragRef.current) return;
    const dx = e.clientX - dragRef.current.startX;
    const dy = e.clientY - dragRef.current.startY;
    if (!dragRef.current.dragging && (Math.abs(dx) > DRAG_THRESHOLD || Math.abs(dy) > DRAG_THRESHOLD)) {
      dragRef.current.dragging = true;
      e.currentTarget.setPointerCapture(e.pointerId);
    }
    if (dragRef.current.dragging) {
      setPan({ x: dragRef.current.startPan.x + dx, y: dragRef.current.startPan.y + dy });
    }
  }, []);

  const onPointerUp = useCallback(() => {
    wasDragRef.current = !!dragRef.current?.dragging;
    dragRef.current = null;
  }, []);

  const fitToView = useCallback(() => {
    const vp = vpRef.current;
    if (!vp || !positions.size) return;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const { x, y } of positions.values()) {
      if (x < minX) minX = x;
      if (y < minY) minY = y;
      if (x + CARD_W > maxX) maxX = x + CARD_W;
      if (y + CARD_H > maxY) maxY = y + CARD_H;
    }
    const pad = 60;
    const w = maxX - minX + pad * 2;
    const h = maxY - minY + pad * 2;
    const rect = vp.getBoundingClientRect();
    const s = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, Math.min(rect.width / w, rect.height / h)));
    setZoom(s);
    setPan({ x: (rect.width - w * s) / 2 - minX * s + pad * s, y: (rect.height - h * s) / 2 - minY * s + pad * s });
  }, [positions]);

  useEffect(() => {
    if (positions.size && zoom === 1 && pan.x === 40 && pan.y === 40) fitToView();
  }, [positions, fitToView, zoom, pan]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card canvas-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div>
            <div className="section-kicker">Discovery</div>
            <h2>탐색 캔버스</h2>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className="canvas-zoom-label">{Math.round(zoom * 100)}%</span>
            <button type="button" className="icon-button" title="화면 맞춤" onClick={fitToView}>⊞</button>
            <button type="button" className="icon-button" title="새로고침" onClick={fetchTree}>↻</button>
            <button type="button" className="ghost-button" onClick={onClose}>닫기</button>
          </div>
        </div>

        <div className="discovery-stats">
          <span>노드 <strong>{stats.total}</strong></span>
          <span>확정 <strong>{stats.confirmed}</strong></span>
          <span>막다른 곳 <strong>{stats.dead_end}</strong></span>
          <span>대기 <strong>{stats.pending}</strong></span>
          <span>최대 깊이 <strong>{stats.maxDepth}</strong></span>
        </div>

        {resumeInfo && resumeInfo.total > 0 ? (
          <div className="callout callout-neutral" style={{ marginTop: 8, padding: "6px 10px", fontSize: "0.9em" }}>
            ↻ 이전 scan 이어받음 (<code>{resumeInfo.prev_run_id.slice(0, 8) || "?"}</code>)
            — endpoint <strong>{resumeInfo.endpoints}</strong>
            · 재검증 vuln <strong>{resumeInfo.vulns}</strong>
            · prev dead_end <strong>{resumeInfo.dead}</strong>
            · clue/exploit <strong>{resumeInfo.clues}</strong>
            <span style={{ opacity: 0.6, marginLeft: 6 }}>(cold-start 회피 + 패치 검증)</span>
          </div>
        ) : null}

        {stats.total > 0 ? (
          <div className="discovery-bar">
            {barSegments.map((seg) => (
              <div key={seg.key} className={`discovery-bar-seg discovery-bar-${seg.key}`} style={{ flex: seg.count }} title={`${seg.label}: ${seg.count}`} />
            ))}
          </div>
        ) : null}

        {error ? <div className="callout callout-error">{error}</div> : null}
        {loading && !nodes.length ? <div className="callout callout-neutral">트리를 불러오는 중...</div> : null}

        <div className="canvas-body">
          <div
            className="canvas-viewport"
            ref={vpRef}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onClick={() => { if (!wasDragRef.current) setSelectedNodeId(null); }}
          >
            <div className="canvas-world" style={{ transform: `translate(${pan.x}px,${pan.y}px) scale(${zoom})` }}>
              <CanvasEdges edges={edges} positions={positions} />
              {allNodes.map((node) => {
                const pos = positions.get(node.node_id);
                if (!pos) return null;
                return <CanvasNode key={node.node_id} node={node} x={pos.x} y={pos.y} selected={selectedNodeId} onSelect={setSelectedNodeId} />;
              })}
            </div>
            {!loading && !allNodes.length && !error ? (
              <div className="canvas-empty callout callout-neutral">이 스캔에는 탐색 노드가 없습니다.</div>
            ) : null}
          </div>

          {selectedNodeId ? (
            <NodeDetailPanel
              node={allNodes.find((n) => n.node_id === selectedNodeId)}
              allNodes={allNodes}
              requests={requests}
              candidates={candidates}
              findings={findings}
              endpointSpecs={endpointSpecs}
              onClose={() => setSelectedNodeId(null)}
            />
          ) : null}
        </div>
      </div>
    </div>
  );
}

function BenchmarkView({ snapshot, now }) {
  if (!snapshot?.scan) {
    return <EmptyState title="실행을 선택하세요" body="벤치마크는 실행을 선택한 뒤 확인할 수 있습니다." className="empty-hero" />;
  }

  const scan = snapshot.scan;
  const summary = snapshot.summary || {};
  const findingsBySeverity = Object.entries(summary.by_severity || {});
  const findingsByType = Object.entries(summary.by_vuln_type || {});
  const totalFindings = summary.total_findings || 0;
  const tokensPerFinding = totalFindings ? Math.round((scan.llm_tokens_used || 0) / totalFindings) : 0;
  const costPerFinding = totalFindings ? Number(scan.llm_cost_usd || 0) / totalFindings : 0;

  return (
    <>
      <div className="benchmark-grid">
        <div className="benchmark-cell"><span className="stat-label">총 취약점</span><strong>{formatCount(totalFindings)}</strong></div>
        <div className="benchmark-cell"><span className="stat-label">건당 토큰</span><strong>{formatCount(tokensPerFinding)}</strong></div>
        <div className="benchmark-cell"><span className="stat-label">건당 비용</span><strong>{formatCurrency(costPerFinding)}</strong></div>
      </div>

      <div className="distribution-grid" style={{ marginTop: 18 }}>
        <div className="distribution-card">
          <strong>심각도 분포</strong>
          {findingsBySeverity.length ? findingsBySeverity.map(([key, count]) => (
            <div key={key} className="distribution-row">
              <span className={`severity-pill severity-${key}`}>{key}</span>
              <div className="distribution-bar"><div className={`distribution-fill fill-${key}`} style={{ width: `${totalFindings ? (count / totalFindings) * 100 : 0}%` }} /></div>
              <span>{count}</span>
            </div>
          )) : <p>아직 집계된 취약점이 없습니다.</p>}
        </div>

        <div className="distribution-card">
          <strong>유형 분포</strong>
          {findingsByType.length ? findingsByType.map(([key, count]) => (
            <div key={key} className="distribution-row">
              <span className="type-pill">{key}</span>
              <div className="distribution-bar"><div className="distribution-fill fill-type" style={{ width: `${totalFindings ? (count / totalFindings) * 100 : 0}%` }} /></div>
              <span>{count}</span>
            </div>
          )) : <p>아직 집계된 취약점이 없습니다.</p>}
        </div>
      </div>

      <SectionCard title="실행 지표" kicker="Benchmark">
        <div className="detail-grid">
          <div><span>대상 URL</span><strong>{scan.target_url}</strong></div>
          <div><span>런타임</span><strong>{formatRuntime(scan, now)}</strong></div>
          <div><span>LLM 호출</span><strong>{formatCount(scan.llm_calls_count)}</strong></div>
          <div><span>총 비용</span><strong>{formatCurrency(scan.llm_cost_usd)}</strong></div>
        </div>
      </SectionCard>
    </>
  );
}

export default function App() {
  const [now, setNow] = useState(Date.now());
  const [historyVisibleCount, setHistoryVisibleCount] = useState(5);
  const [historyListHeight, setHistoryListHeight] = useState(null);

  const [scanListSnapshot, setScanListSnapshot] = useState({ scans: [], emitted_at: null });
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [expandedTarget, setExpandedTarget] = useState(null);
  const [runSnapshot, setRunSnapshot] = useState(null);
  const [llmTraceSnapshot, setLlmTraceSnapshot] = useState({ traces: [], count: 0 });

  const [showNewScan, setShowNewScan] = useState(false);
  const [showRunDetails, setShowRunDetails] = useState(false);
  const [showFindingsModal, setShowFindingsModal] = useState(false);
  const [showCandidatesModal, setShowCandidatesModal] = useState(false);
  const [showLlmTrace, setShowLlmTrace] = useState(false);
  const [showDiscoveryTree, setShowDiscoveryTree] = useState(false);
  const [showApiSpecs, setShowApiSpecs] = useState(false);

  const [selectedFindingId, setSelectedFindingId] = useState(null);
  const [findingDetail, setFindingDetail] = useState(null);

  const [listError, setListError] = useState("");
  const [detailError, setDetailError] = useState("");
  const [llmTraceError, setLlmTraceError] = useState("");
  const [findingError, setFindingError] = useState("");

  const [detailLoading, setDetailLoading] = useState(false);
  const [llmTraceLoading, setLlmTraceLoading] = useState(false);
  const [findingLoading, setFindingLoading] = useState(false);
  const [stopLoading, setStopLoading] = useState(false);

  const visibleScans = useMemo(() => scanListSnapshot.scans, [scanListSnapshot.scans]);
  const scanGroups = useMemo(() => groupScansByTarget(visibleScans), [visibleScans]);
  const displayedScans = useMemo(
    () => visibleScans.slice(0, historyVisibleCount),
    [visibleScans, historyVisibleCount]
  );

  const currentScan = runSnapshot?.scan || null;
  const findings = runSnapshot?.summary?.findings || [];

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  async function refreshScanList() {
    try {
      const snapshot = await fetchScanListSnapshot();
      setScanListSnapshot(snapshot);
      setListError("");
    } catch (error) {
      setListError(error.message);
    }
  }

  async function refreshSelectedRun(runId = selectedRunId) {
    if (!runId) return;

    setDetailLoading(true);
    try {
      const snapshot = await fetchScanRunSnapshot(runId);
      setRunSnapshot(snapshot);
      setDetailError("");
    } catch (error) {
      setDetailError(error.message);
    } finally {
      setDetailLoading(false);
    }
  }

  async function refreshLlmTraces(runId = selectedRunId) {
    if (!runId) return;

    setLlmTraceLoading(true);
    try {
      const payload = await fetchLlmTraces(runId);
      setLlmTraceSnapshot(payload);
      setLlmTraceError("");
    } catch (error) {
      setLlmTraceError(error.message);
    } finally {
      setLlmTraceLoading(false);
    }
  }

  useEffect(() => {
    refreshScanList();
  }, []);

  useEffect(() => {
    let socket;

    try {
      socket = new WebSocket(wsUrl("/ws/scans/"));
      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "scan_list_snapshot" || Array.isArray(payload.scans)) {
            setScanListSnapshot({
              scans: normalizePaginatedList(payload),
              emitted_at: payload.emitted_at || new Date().toISOString(),
            });
            setListError("");
          }
        } catch {
          setListError("실시간 스캔 목록 데이터를 해석하지 못했습니다.");
        }
      };
      socket.onerror = () => setListError("실시간 스캔 목록 연결이 불안정합니다.");
    } catch {
      setListError("실시간 스캔 목록 연결을 열지 못했습니다.");
    }

    return () => {
      if (socket) socket.close();
    };
  }, []);

  useEffect(() => {
    if (!visibleScans.length) {
      setSelectedRunId(null);
      setRunSnapshot(null);
      return;
    }

    const stillVisible = visibleScans.some((scan) => scan.run_id === selectedRunId);
    if (!selectedRunId || !stillVisible) {
      setSelectedRunId(visibleScans[0].run_id);
    }
  }, [visibleScans, selectedRunId]);

  useEffect(() => {
    if (!selectedRunId || !scanGroups.length) return;
    const group = scanGroups.find((g) => g.runs.some((s) => s.run_id === selectedRunId));
    if (group && group.runs.length > 1) {
      setExpandedTarget(group.targetUrl);
    }
  }, [selectedRunId, scanGroups]);

  useEffect(() => {
    if (!visibleScans.length) {
      setHistoryVisibleCount(5);
      return;
    }

    if (historyVisibleCount > visibleScans.length) {
      setHistoryVisibleCount(Math.max(5, visibleScans.length));
      return;
    }

    if (selectedRunId) {
      const selectedIndex = visibleScans.findIndex((scan) => scan.run_id === selectedRunId);
      if (selectedIndex >= historyVisibleCount) {
        setHistoryVisibleCount(Math.ceil((selectedIndex + 1) / 5) * 5);
      }
    }
  }, [visibleScans, historyVisibleCount, selectedRunId]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const listNode = document.getElementById("scan-card-list-inner");
      setHistoryListHeight(listNode ? listNode.scrollHeight : null);
    });

    return () => window.cancelAnimationFrame(frame);
  }, [displayedScans]);

  useEffect(() => {
    if (!selectedRunId) return undefined;

    refreshSelectedRun(selectedRunId);

    let socket;
    try {
      socket = new WebSocket(wsUrl(`/ws/scan-runs/${selectedRunId}/`));
      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "scan_run_snapshot" || payload.scan) {
            setRunSnapshot(payload);
            setDetailError("");
          }
        } catch {
          setDetailError("실시간 스캔 상세 데이터를 해석하지 못했습니다.");
        }
      };
      socket.onerror = () => setDetailError("실시간 스캔 상세 연결이 불안정합니다.");
    } catch {
      setDetailError("실시간 스캔 상세 연결을 열지 못했습니다.");
    }

    return () => {
      if (socket) socket.close();
    };
  }, [selectedRunId]);

  useEffect(() => {
    if (!showFindingsModal) return;

    if (!findings.length) {
      setSelectedFindingId(null);
      setFindingDetail(null);
      return;
    }

    const stillExists = findings.some((finding) => finding.finding_id === selectedFindingId);
    if (!selectedFindingId || !stillExists) {
      setSelectedFindingId(findings[0].finding_id);
    }
  }, [showFindingsModal, findings, selectedFindingId]);

  useEffect(() => {
    if (!showFindingsModal || !selectedFindingId) return;

    let cancelled = false;
    setFindingLoading(true);
    fetchFindingDetail(selectedFindingId)
      .then((payload) => {
        if (cancelled) return;
        setFindingDetail(payload);
        setFindingError("");
      })
      .catch((error) => {
        if (cancelled) return;
        setFindingError(error.message);
      })
      .finally(() => {
        if (!cancelled) setFindingLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [showFindingsModal, selectedFindingId]);

  useEffect(() => {
    if (!showLlmTrace || !selectedRunId) return;
    refreshLlmTraces(selectedRunId);
  }, [showLlmTrace, selectedRunId]);

  async function handleStopRun() {
    if (!selectedRunId) return;

    setStopLoading(true);
    try {
      await apiPost(`/api/scan-runs/${selectedRunId}/stop/`);
      await Promise.all([refreshSelectedRun(selectedRunId), refreshScanList()]);
      setDetailError("");
    } catch (error) {
      setDetailError(error.message);
    } finally {
      setStopLoading(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <div className="brand-row">
            <div className="brand-mark">WATCHDOG</div>
          </div>
        </div>

        <div className="header-actions">
          <button type="button" className="primary-button" onClick={() => setShowNewScan(true)}>
            새 스캔
          </button>
        </div>
      </header>

      <div className="workspace">
        <aside className="history-rail">
          <div className="rail-head">
            <div className="rail-title-stack">
              <div className="section-kicker">Queue</div>
              <h2>스캔 히스토리</h2>
              
            </div>

            <div className="header-actions">
              <button
                type="button"
                className="icon-button"
                title="목록 새로고침"
                onClick={refreshScanList}
              >
                ↻
              </button>
            </div>
          </div>

          <div className="rail-summary">
              <div className="rail-summary-pill">
                <strong>{formatCount(scanGroups.length)}개 타겟 · {formatCount(visibleScans.length)}회 스캔</strong>
              </div>
          </div>

          {listError ? <div className="callout callout-error">{listError}</div> : null}

          <div className="scan-card-list-shell">
            <div id="scan-card-list-inner" className="scan-card-list">
              {scanGroups.length ? (
                scanGroups.map((group) => (
                  <ScanGroup
                    key={group.targetUrl}
                    group={group}
                    selectedRunId={selectedRunId}
                    onSelect={setSelectedRunId}
                    now={now}
                    expandedTarget={expandedTarget}
                    onToggle={setExpandedTarget}
                  />
                ))
              ) : (
                <EmptyState
                  title="표시 중인 스캔이 없습니다"
                  body="새 스캔을 시작하거나, 숨긴 기록을 복원해 목록을 다시 채워보세요."
                />
              )}
            </div>
          </div>
        </aside>

        <main className="content-stage">
          {detailError ? <div className="callout callout-error">{detailError}</div> : null}
          {detailLoading && !runSnapshot ? (
            <div className="callout callout-neutral">선택한 스캔 상태를 불러오는 중입니다...</div>
          ) : null}

          <ResultsView
            snapshot={runSnapshot}
            now={now}
            onRefresh={() => refreshSelectedRun()}
            onOpenFindings={() => setShowFindingsModal(true)}
            onOpenCandidates={() => setShowCandidatesModal(true)}
            onOpenRunDetails={() => setShowRunDetails(true)}
            onOpenLlmTrace={() => setShowLlmTrace(true)}
            onOpenDiscoveryTree={() => setShowDiscoveryTree(true)}
            onOpenApiSpecs={() => setShowApiSpecs(true)}
            onStop={handleStopRun}
            stopLoading={stopLoading}
          />
        </main>
      </div>

      {showNewScan ? (
        <NewScanModal
          onClose={() => setShowNewScan(false)}
          onCreated={(runId) => {
            setShowNewScan(false);
            setSelectedRunId(runId);
            refreshScanList();
          }}
        />
      ) : null}

      {showRunDetails ? (
        <RunDetailsModal
          scan={currentScan}
          requestCount={runSnapshot?.request_catalog_count || 0}
          candidateCount={runSnapshot?.candidate_count || runSnapshot?.candidates?.length || 0}
          onClose={() => setShowRunDetails(false)}
        />
      ) : null}

      {showFindingsModal ? (
        <FindingsModal
          findings={findings}
          detail={findingDetail}
          loading={findingLoading}
          error={findingError}
          selectedFindingId={selectedFindingId}
          onSelect={setSelectedFindingId}
          onClose={() => setShowFindingsModal(false)}
        />
      ) : null}

      {showCandidatesModal ? (
        <CandidatesModal
          candidates={runSnapshot?.candidates || []}
          onClose={() => setShowCandidatesModal(false)}
        />
      ) : null}

      {showLlmTrace ? (
        <LlmTraceModal
          scan={currentScan}
          traces={llmTraceSnapshot.traces}
          loading={llmTraceLoading}
          error={llmTraceError}
          onRefresh={() => refreshLlmTraces()}
          onClose={() => setShowLlmTrace(false)}
        />
      ) : null}

      {showDiscoveryTree && selectedRunId ? (
        <DiscoveryTreeModal
          runId={selectedRunId}
          scanStatus={currentScan?.status}
          onClose={() => setShowDiscoveryTree(false)}
        />
      ) : null}

      {showApiSpecs && selectedRunId ? (
        <EndpointSpecModal
          runId={selectedRunId}
          targetUrl={currentScan?.target_url}
          onClose={() => setShowApiSpecs(false)}
        />
      ) : null}
    </div>
  );
}
