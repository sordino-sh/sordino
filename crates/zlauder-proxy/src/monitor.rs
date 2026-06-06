//! Local realtime request monitor and optional approval gate.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::response::Response;
use futures::{StreamExt, stream};
use http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;
use zlauder_engine::{CustomReplacement, UnmaskManifest};

use crate::admin::WireConfig;
use crate::routes;
use crate::state::AppState;

const MAX_RECORDS: usize = 500;
const PREVIEW_LIMIT: usize = 128 * 1024;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_MAX_PENDING_APPROVALS: usize = 32;

#[derive(Clone)]
pub struct Monitor {
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<MonitorEvent>,
}

struct Inner {
    mode: MonitorMode,
    max_pending_approvals: usize,
    next_seq: u64,
    records: VecDeque<RequestRecord>,
    waiters: HashMap<String, oneshot::Sender<ApprovalDecision>>,
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Monitor {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                mode: MonitorMode::Off,
                max_pending_approvals: DEFAULT_MAX_PENDING_APPROVALS,
                next_seq: 1,
                records: VecDeque::new(),
                waiters: HashMap::new(),
            })),
            events,
        }
    }

    pub fn snapshot(&self) -> MonitorSnapshot {
        let inner = self.inner.lock().expect("monitor mutex poisoned");
        MonitorSnapshot {
            mode: inner.mode,
            pending_count: inner.waiters.len(),
            max_pending_approvals: inner.max_pending_approvals,
            records: inner.records.iter().cloned().collect(),
        }
    }

    pub fn set_mode(
        &self,
        mode: MonitorMode,
        max_pending_approvals: Option<usize>,
    ) -> MonitorSnapshot {
        {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            inner.mode = mode;
            if let Some(max) = max_pending_approvals {
                inner.max_pending_approvals = max;
            }
        }
        let snap = self.snapshot();
        self.emit(MonitorEvent::Snapshot(snap.clone()));
        snap
    }

    pub fn record_llm_request(
        &self,
        endpoint: &'static str,
        method: &str,
        conversation_id: Option<String>,
        masked_body: &[u8],
        manifest: &UnmaskManifest,
    ) -> ReviewTicket {
        let mut inner = self.inner.lock().expect("monitor mutex poisoned");
        let id = format!("req-{}", inner.next_seq);
        inner.next_seq += 1;
        let should_hold = match inner.mode {
            MonitorMode::Off => false,
            MonitorMode::ManualAllLlm => true,
            MonitorMode::ManualOnDetection => !manifest.is_empty(),
        };
        let now = now_ms();
        let request_preview = preview(masked_body);
        let tokens = token_previews(manifest);
        let request_spans = spans_from_manifest(manifest, &request_preview);
        let pending_full = should_hold && inner.waiters.len() >= inner.max_pending_approvals;
        let (status, rx, immediate_reject) = if pending_full {
            (
                RequestDecision::BackpressureRejected,
                None,
                Some(format!(
                    "pending approval limit reached ({})",
                    inner.max_pending_approvals
                )),
            )
        } else if should_hold {
            let (tx, rx) = oneshot::channel();
            inner.waiters.insert(id.clone(), tx);
            (RequestDecision::Pending, Some(rx), None)
        } else {
            (RequestDecision::AutoAccepted, None, None)
        };
        let record = RequestRecord {
            id: id.clone(),
            conversation_id: conversation_id.unwrap_or_else(|| "unknown".to_string()),
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            started_ms: now,
            updated_ms: now,
            decision: status,
            request_preview,
            request_spans,
            response_preview: None,
            response_spans: Vec::new(),
            response_status: None,
            tokens,
            tags: Vec::new(),
            rejection_reason: immediate_reject.clone(),
        };
        push_record(&mut inner.records, record.clone());
        drop(inner);
        self.emit(MonitorEvent::Record(record.clone()));
        ReviewTicket {
            id,
            rx,
            immediate_reject,
        }
    }

    pub fn record_response(&self, id: &str, status: StatusCode, body: Option<&[u8]>) {
        self.update_record(id, |r| {
            r.response_status = Some(status.as_u16());
            r.response_preview = body.map(preview);
            r.response_spans = r
                .response_preview
                .as_deref()
                .map(|p| spans_from_values(&r.tokens, p))
                .unwrap_or_default();
            if !matches!(
                r.decision,
                RequestDecision::Rejected
                    | RequestDecision::TimedOut
                    | RequestDecision::BackpressureRejected
            ) {
                r.decision = RequestDecision::Completed;
            }
        });
    }

    pub fn record_upstream_error(&self, id: &str, msg: &str) {
        self.update_record(id, |r| {
            r.decision = RequestDecision::UpstreamError;
            r.rejection_reason = Some(msg.to_string());
        });
    }

    async fn wait_for_approval(&self, ticket: ReviewTicket) -> ApprovalDecision {
        let Some(rx) = ticket.rx else {
            if let Some(reason) = ticket.immediate_reject {
                return ApprovalDecision::Reject { reason };
            }
            return ApprovalDecision::Approve;
        };
        match tokio::time::timeout(APPROVAL_TIMEOUT, rx).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) => ApprovalDecision::Reject {
                reason: "approval channel closed".to_string(),
            },
            Err(_) => {
                let mut inner = self.inner.lock().expect("monitor mutex poisoned");
                inner.waiters.remove(&ticket.id);
                drop(inner);
                self.update_record(&ticket.id, |r| {
                    r.decision = RequestDecision::TimedOut;
                    r.rejection_reason = Some("approval timed out".to_string());
                });
                ApprovalDecision::Reject {
                    reason: "approval timed out".to_string(),
                }
            }
        }
    }

    fn decide(&self, id: &str, decision: ApprovalDecision) -> Result<RequestRecord, StatusCode> {
        let waiter = {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            inner.waiters.remove(id)
        };
        let Some(waiter) = waiter else {
            return Err(StatusCode::NOT_FOUND);
        };
        let _ = waiter.send(decision.clone());
        let mut out = None;
        self.update_record(id, |r| {
            match &decision {
                ApprovalDecision::Approve => r.decision = RequestDecision::Approved,
                ApprovalDecision::Reject { reason } => {
                    r.decision = RequestDecision::Rejected;
                    r.rejection_reason = Some(reason.clone());
                }
            }
            out = Some(r.clone());
        });
        out.ok_or(StatusCode::NOT_FOUND)
    }

    fn update_tags(&self, id: &str, tags: Vec<String>) -> Result<RequestRecord, StatusCode> {
        let mut out = None;
        self.update_record(id, |r| {
            r.tags = tags.clone();
            out = Some(r.clone());
        });
        out.ok_or(StatusCode::NOT_FOUND)
    }

    fn update_record(&self, id: &str, f: impl FnOnce(&mut RequestRecord)) {
        let mut changed = None;
        {
            let mut inner = self.inner.lock().expect("monitor mutex poisoned");
            if let Some(r) = inner.records.iter_mut().find(|r| r.id == id) {
                f(r);
                r.updated_ms = now_ms();
                changed = Some(r.clone());
            }
        }
        if let Some(record) = changed {
            self.emit(MonitorEvent::Record(record));
        }
    }

    fn emit(&self, event: MonitorEvent) {
        let _ = self.events.send(event);
    }

    fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.events.subscribe()
    }
}

pub struct ReviewTicket {
    id: String,
    rx: Option<oneshot::Receiver<ApprovalDecision>>,
    immediate_reject: Option<String>,
}

impl ReviewTicket {
    pub fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorMode {
    Off,
    ManualAllLlm,
    ManualOnDetection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum ApprovalDecision {
    Approve,
    Reject { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestDecision {
    AutoAccepted,
    Pending,
    Approved,
    Rejected,
    BackpressureRejected,
    TimedOut,
    UpstreamError,
    Completed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestRecord {
    pub id: String,
    pub conversation_id: String,
    pub endpoint: String,
    pub method: String,
    pub started_ms: u128,
    pub updated_ms: u128,
    pub decision: RequestDecision,
    pub request_preview: String,
    pub request_spans: Vec<PreviewSpan>,
    pub response_preview: Option<String>,
    pub response_spans: Vec<PreviewSpan>,
    pub response_status: Option<u16>,
    pub tokens: Vec<TokenPreview>,
    pub tags: Vec<String>,
    pub rejection_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenPreview {
    pub token: String,
    pub value: String,
    pub entity_kind: String,
    pub surface: String,
    pub request_start: Option<usize>,
    pub request_end: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreviewSpan {
    pub start: usize,
    pub end: usize,
    pub token: String,
    pub entity_kind: String,
    pub surface: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorSnapshot {
    pub mode: MonitorMode,
    pub pending_count: usize,
    pub max_pending_approvals: usize,
    pub records: Vec<RequestRecord>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "event", content = "data")]
enum MonitorEvent {
    Snapshot(MonitorSnapshot),
    Record(RequestRecord),
}

#[derive(Deserialize)]
pub struct ModeRequest {
    mode: MonitorMode,
    #[serde(default)]
    max_pending_approvals: Option<usize>,
}

#[derive(Deserialize)]
pub struct RejectRequest {
    #[serde(default)]
    reason: String,
}

#[derive(Deserialize)]
pub struct TagsRequest {
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
pub struct CustomMaskRequest {
    pattern: String,
    #[serde(default)]
    entity_type: Option<String>,
    #[serde(default = "default_true")]
    case_sensitive: bool,
}

fn default_true() -> bool {
    true
}

pub async fn snapshot(State(st): State<AppState>, hdrs: HeaderMap) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    json_response(&st.monitor.snapshot())
}

pub async fn set_mode(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    axum::Json(req): axum::Json<ModeRequest>,
) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    json_response(&st.monitor.set_mode(req.mode, req.max_pending_approvals))
}

pub async fn approve(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    match st.monitor.decide(&id, ApprovalDecision::Approve) {
        Ok(r) => json_response(&r),
        Err(s) => text(s, "unknown or non-pending request"),
    }
}

pub async fn reject(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(id): Path<String>,
    axum::Json(req): axum::Json<RejectRequest>,
) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    let reason = if req.reason.trim().is_empty() {
        "rejected by monitor".to_string()
    } else {
        req.reason
    };
    match st.monitor.decide(&id, ApprovalDecision::Reject { reason }) {
        Ok(r) => json_response(&r),
        Err(s) => text(s, "unknown or non-pending request"),
    }
}

pub async fn tags(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Path(id): Path<String>,
    axum::Json(req): axum::Json<TagsRequest>,
) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    match st.monitor.update_tags(&id, req.tags) {
        Ok(r) => json_response(&r),
        Err(s) => text(s, "unknown request"),
    }
}

pub async fn custom_mask(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    axum::Json(req): axum::Json<CustomMaskRequest>,
) -> Response {
    if !st.authed(&hdrs) {
        return forbidden();
    }
    let pattern = req.pattern.trim();
    if pattern.is_empty() {
        return text(StatusCode::BAD_REQUEST, "pattern must not be empty");
    }
    let mut cfg = st.engine.config_snapshot();
    cfg.custom_replacements.push(CustomReplacement {
        pattern: pattern.to_string(),
        entity_type: req
            .entity_type
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "CUSTOM_KEYWORD".to_string()),
        is_regex: false,
        case_sensitive: req.case_sensitive,
        priority: 0,
        literal_token: false,
        token: None,
        apply_to_surfaces: None,
    });
    if let Err(e) = st.engine.set_config(cfg) {
        return text(
            StatusCode::BAD_REQUEST,
            &format!("custom mask rejected: {e}"),
        );
    }
    let wire = WireConfig::from_engine(&st.engine.config_snapshot());
    json_response(&json!({ "ok": true, "config": wire }))
}

pub async fn events(
    State(st): State<AppState>,
    hdrs: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if !st.authed(&hdrs) && query.get("key") != Some(st.admin_key.as_ref()) {
        return forbidden();
    }
    let snapshot = st.monitor.snapshot();
    let rx = st.monitor.subscribe();
    let initial = stream::once(async move {
        Ok::<Bytes, Infallible>(Bytes::from(sse_frame(&MonitorEvent::Snapshot(snapshot))))
    });
    let updates = stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => return Some((Ok(Bytes::from(sse_frame(&ev))), rx)),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    let mut r = Response::new(Body::from_stream(initial.chain(updates)));
    r.headers_mut()
        .insert(CONTENT_TYPE, "text/event-stream".parse().unwrap());
    r
}

pub async fn ui() -> Response {
    let mut r = Response::new(Body::from(UI_HTML));
    r.headers_mut()
        .insert(CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    r
}

pub async fn maybe_approve(st: &AppState, ticket: ReviewTicket) -> Result<(), Response> {
    match st.monitor.wait_for_approval(ticket).await {
        ApprovalDecision::Approve => Ok(()),
        ApprovalDecision::Reject { reason } => Err(routes::err(
            StatusCode::FORBIDDEN,
            &format!("zlauder monitor rejected request: {reason}"),
        )),
    }
}

pub fn conversation_from_headers(hdrs: &HeaderMap) -> Option<String> {
    hdrs.get("x-zlauder-conversation")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn push_record(records: &mut VecDeque<RequestRecord>, record: RequestRecord) {
    records.push_front(record);
    while records.len() > MAX_RECORDS {
        records.pop_back();
    }
}

fn token_previews(manifest: &UnmaskManifest) -> Vec<TokenPreview> {
    manifest
        .entries
        .iter()
        .map(|e| TokenPreview {
            token: e.token_handle.clone(),
            value: e.canonical_form.clone(),
            entity_kind: e.entity_kind.clone(),
            surface: format!("{:?}", e.arrow_origin),
            request_start: e.exposed_at.as_ref().map(|r| r.start),
            request_end: e.exposed_at.as_ref().map(|r| r.end),
        })
        .collect()
}

fn spans_from_manifest(manifest: &UnmaskManifest, preview: &str) -> Vec<PreviewSpan> {
    let mut spans: Vec<PreviewSpan> = manifest
        .entries
        .iter()
        .filter_map(|e| {
            let r = e.exposed_at.as_ref()?;
            if r.start >= r.end || r.end > preview.len() {
                return None;
            }
            Some(PreviewSpan {
                start: r.start,
                end: r.end,
                token: e.token_handle.clone(),
                entity_kind: e.entity_kind.clone(),
                surface: format!("{:?}", e.arrow_origin),
            })
        })
        .collect();
    spans.sort_by_key(|s| (s.start, s.end));
    spans
}

fn spans_from_values(tokens: &[TokenPreview], preview: &str) -> Vec<PreviewSpan> {
    let mut spans = Vec::new();
    for t in tokens {
        if t.value.is_empty() {
            continue;
        }
        let mut search_from = 0;
        while search_from < preview.len() {
            let Some(rel) = preview[search_from..].find(&t.value) else {
                break;
            };
            let start = search_from + rel;
            let end = start + t.value.len();
            spans.push(PreviewSpan {
                start,
                end,
                token: t.token.clone(),
                entity_kind: t.entity_kind.clone(),
                surface: t.surface.clone(),
            });
            search_from = end;
        }
    }
    spans.sort_by_key(|s| (s.start, s.end));
    dedupe_overlapping_spans(spans)
}

fn dedupe_overlapping_spans(spans: Vec<PreviewSpan>) -> Vec<PreviewSpan> {
    let mut out: Vec<PreviewSpan> = Vec::new();
    for span in spans {
        if out.iter().any(|s| span.start < s.end && s.start < span.end) {
            continue;
        }
        out.push(span);
    }
    out
}

fn preview(body: &[u8]) -> String {
    let clipped = if body.len() > PREVIEW_LIMIT {
        &body[..PREVIEW_LIMIT]
    } else {
        body
    };
    let mut s = String::from_utf8_lossy(clipped).to_string();
    if body.len() > PREVIEW_LIMIT {
        s.push_str("\n...[truncated]");
    }
    s
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn sse_frame(ev: &MonitorEvent) -> String {
    let data = serde_json::to_string(ev).unwrap_or_else(|_| "{}".to_string());
    format!("data: {data}\n\n")
}

fn json_response(v: &impl Serialize) -> Response {
    let mut r = Response::new(Body::from(serde_json::to_vec(v).unwrap_or_default()));
    r.headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
    r
}

fn forbidden() -> Response {
    text(StatusCode::FORBIDDEN, "missing or invalid x-zlauder-key")
}

fn text(status: StatusCode, msg: &str) -> Response {
    let mut r = Response::new(Body::from(msg.to_string()));
    *r.status_mut() = status;
    r
}

pub fn random_conversation_id() -> String {
    Uuid::new_v4().to_string()
}

const UI_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZlauDeR Monitor</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#1f2328;background:#f6f8fa}
body{margin:0}
header{height:52px;display:flex;align-items:center;gap:12px;padding:0 16px;border-bottom:1px solid #d0d7de;background:#fff}
h1{font-size:16px;margin:0;font-weight:650}
button,select,input{font:inherit}
button{border:1px solid #8c959f;background:#fff;border-radius:6px;padding:6px 10px;cursor:pointer}
button.primary{background:#0969da;color:#fff;border-color:#0969da}
button.danger{background:#cf222e;color:#fff;border-color:#cf222e}
main{display:grid;grid-template-columns:220px minmax(280px,1fr) minmax(360px,45vw);height:calc(100vh - 53px)}
aside,.list,.detail{overflow:auto}
aside{border-right:1px solid #d0d7de;background:#fff;padding:12px}
.list{border-right:1px solid #d0d7de}
.row{padding:10px 12px;border-bottom:1px solid #d8dee4;cursor:pointer;background:#fff}
.row:hover,.row.active{background:#eef6ff}
.row.pending{border-left:4px solid #bf8700}
.meta{font-size:12px;color:#57606a;margin-top:4px}
.detail{padding:14px}
.panel{background:#fff;border:1px solid #d0d7de;border-radius:8px;margin-bottom:12px}
.panel h2{font-size:13px;margin:0;padding:10px 12px;border-bottom:1px solid #d8dee4}
.panel .body{padding:12px}
pre{white-space:pre-wrap;word-break:break-word;margin:0;font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
.token{display:inline-block;border:1px solid #d0d7de;border-radius:6px;padding:4px 6px;margin:3px;background:#fff8c5;font-size:12px}
.mark{background:#fff8c5;border-bottom:2px solid #bf8700;border-radius:3px;padding:0 1px}
.queue{font-size:12px;color:#57606a}
.spacer{flex:1}
.empty{padding:24px;color:#57606a}
</style>
</head>
<body>
<header>
  <h1>ZlauDeR Monitor</h1>
  <select id="mode">
    <option value="off">Monitor only</option>
    <option value="manual_all_llm">Approve all LLM calls</option>
    <option value="manual_on_detection">Approve when tokens detected</option>
  </select>
  <button id="saveMode">Set mode</button>
  <span class="queue" id="queue"></span>
  <span class="spacer"></span>
  <input id="tagInput" placeholder="tag selected request">
  <button id="tagBtn">Tag</button>
  <button id="maskBtn">Mask selection</button>
</header>
<main>
  <aside><strong>Conversations</strong><div id="sessions"></div></aside>
  <section class="list" id="records"></section>
  <section class="detail" id="detail"><div class="empty">Select a request.</div></section>
</main>
<script>
let key=new URLSearchParams(location.search).get('key')||localStorage.getItem('zlauderKey')||'';
if(key){localStorage.setItem('zlauderKey',key);history.replaceState(null,'',location.pathname)}
if(!key){key=prompt('x-zlauder-key')||'';localStorage.setItem('zlauderKey',key)}
let records=[], selected=null;
const hdr={'x-zlauder-key':key,'content-type':'application/json'};
function api(path,opts={}){opts.headers={...(opts.headers||{}),...hdr};return fetch(path,opts)}
function render(){
  const mode=document.getElementById('mode');
  const bySession=[...new Set(records.map(r=>r.conversation_id))];
  document.getElementById('sessions').innerHTML=bySession.map(s=>`<div class="meta">${esc(s)}</div>`).join('');
  document.getElementById('records').innerHTML=records.map(r=>`<div class="row ${r.decision==='pending'?'pending':''} ${selected===r.id?'active':''}" onclick="selectReq('${r.id}')"><strong>${esc(r.endpoint)}</strong><div class="meta">${esc(r.decision)} · ${r.tokens.length} token(s) · ${esc(r.conversation_id)}</div></div>`).join('')||'<div class="empty">No requests yet.</div>';
  const r=records.find(x=>x.id===selected);
  const d=document.getElementById('detail');
  if(!r){d.innerHTML='<div class="empty">Select a request.</div>';return}
  d.innerHTML=`<div class="panel"><h2>Decision</h2><div class="body"><strong>${esc(r.decision)}</strong> ${r.response_status||''}<div class="meta">${esc((r.tags||[]).join(', '))}</div>${r.rejection_reason?`<div class="meta">${esc(r.rejection_reason)}</div>`:''}${r.decision==='pending'?`<p><button class="primary" onclick="approve('${r.id}')">Approve</button> <button class="danger" onclick="rejectReq('${r.id}')">Reject</button></p>`:''}</div></div><div class="panel"><h2>Tokens</h2><div class="body">${r.tokens.map(t=>`<span class="token" title="${esc(t.value)}">${esc(t.entity_kind)} ${esc(t.token)}</span>`).join('')||'<span class="meta">No tokens</span>'}</div></div><div class="panel"><h2>Masked Request</h2><div class="body"><pre>${renderPreview(r.request_preview,r.request_spans||[])}</pre></div></div><div class="panel"><h2>Response Preview</h2><div class="body"><pre>${renderPreview(r.response_preview||'',r.response_spans||[])}</pre></div></div>`;
}
window.selectReq=id=>{selected=id;render()}
window.approve=id=>api(`/zlauder/monitor/requests/${id}/approve`,{method:'POST'}).then(load)
window.rejectReq=id=>api(`/zlauder/monitor/requests/${id}/reject`,{method:'POST',body:JSON.stringify({reason:'rejected in monitor'})}).then(load)
document.getElementById('saveMode').onclick=()=>api('/zlauder/monitor/mode',{method:'POST',body:JSON.stringify({mode:document.getElementById('mode').value})}).then(load)
document.getElementById('tagBtn').onclick=()=>{if(!selected)return;api(`/zlauder/monitor/requests/${selected}/tags`,{method:'POST',body:JSON.stringify({tags:[document.getElementById('tagInput').value].filter(Boolean)})}).then(load)}
document.getElementById('maskBtn').onclick=()=>{const s=getSelection().toString().trim();if(s)api('/zlauder/monitor/custom-mask',{method:'POST',body:JSON.stringify({pattern:s})}).then(load)}
function load(){api('/zlauder/monitor/snapshot').then(r=>r.json()).then(s=>{records=s.records;document.getElementById('mode').value=s.mode;document.getElementById('queue').textContent=`pending ${s.pending_count}/${s.max_pending_approvals}`;render()})}
function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function renderPreview(text,spans){
  text=String(text||''); spans=[...(spans||[])].sort((a,b)=>a.start-b.start);
  let out='', cursor=0;
  for(const s of spans){
    if(s.start<cursor||s.end>text.length||s.start>=s.end)continue;
    out+=esc(text.slice(cursor,s.start));
    out+=`<span class="mark" title="${esc(s.entity_kind)} ${esc(s.token)}">${esc(text.slice(s.start,s.end))}</span>`;
    cursor=s.end;
  }
  return out+esc(text.slice(cursor));
}
load();
const es=new EventSource(`/zlauder/monitor/events?key=${encodeURIComponent(key)}`);
es.onmessage=e=>{const ev=JSON.parse(e.data); if(ev.event==='snapshot'){records=ev.data.records;document.getElementById('mode').value=ev.data.mode;document.getElementById('queue').textContent=`pending ${ev.data.pending_count}/${ev.data.max_pending_approvals}`}else if(ev.event==='record'){records=[ev.data,...records.filter(r=>r.id!==ev.data.id)]} render()}
</script>
</body>
</html>"#;
