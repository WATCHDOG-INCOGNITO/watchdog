import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = "http://localhost:8000";
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

function ScanCard({ scan, selected, onSelect, now }) {
  const statusMeta = getEffectiveStatus(scan, now);

  return (
    <article className={`scan-card ${selected ? "selected" : ""}`}>
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

        <div className="scan-target">{scan.target_url}</div>
        <div className="scan-meta-row">
          <span>{formatDateTime(scan.created_at)}</span>
          <span>{String(scan.run_id).slice(0, 8)}</span>
        </div>
      </button>
    </article>
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
  const [runSnapshot, setRunSnapshot] = useState(null);
  const [llmTraceSnapshot, setLlmTraceSnapshot] = useState({ traces: [], count: 0 });

  const [showNewScan, setShowNewScan] = useState(false);
  const [showRunDetails, setShowRunDetails] = useState(false);
  const [showFindingsModal, setShowFindingsModal] = useState(false);
  const [showCandidatesModal, setShowCandidatesModal] = useState(false);
  const [showLlmTrace, setShowLlmTrace] = useState(false);

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
                <strong>전체:{formatCount(visibleScans.length)}</strong>
              </div>
          </div>

          {listError ? <div className="callout callout-error">{listError}</div> : null}

          <div className="scan-card-list-shell" style={{ maxHeight: historyListHeight ? `${historyListHeight}px` : undefined }}>
            <div id="scan-card-list-inner" className="scan-card-list">
              {visibleScans.length ? (
                displayedScans.map((scan) => (
                  <ScanCard
                    key={scan.run_id}
                    scan={scan}
                    selected={scan.run_id === selectedRunId}
                    onSelect={setSelectedRunId}
                    now={now}
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

          {visibleScans.length > displayedScans.length ? (
            <div className="history-more-actions">
              <button
                type="button"
                className="ghost-button history-more-button"
                onClick={() => setHistoryVisibleCount((current) => current + 5)}
              >
                더보기
              </button>
              {historyVisibleCount > 5 ? (
                <button
                  type="button"
                  className="ghost-button history-more-button"
                  onClick={() => setHistoryVisibleCount(5)}
                >
                  접기
                </button>
              ) : null}
            </div>
          ) : null}
          {visibleScans.length <= displayedScans.length && historyVisibleCount > 5 ? (
            <button
              type="button"
              className="ghost-button history-more-button"
              onClick={() => setHistoryVisibleCount(5)}
            >
              접기
            </button>
          ) : null}
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
    </div>
  );
}
