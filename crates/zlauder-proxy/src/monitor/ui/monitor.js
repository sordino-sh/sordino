/* ============================================================
   ZLAUDER INTERCEPT STATION  -  frontend controller
   Binds to the exact serde contract emitted by monitor/model.rs:
     MonitorSnapshot { mode, pending_count, max_pending_approvals,
                       approval_timeout_secs, records[], conversations[] }
     RequestRecord   { id, conversation_id, endpoint, method, started_ms,
                       updated_ms, decision, request_preview, request_spans,
                       response_preview, response_spans, response_status,
                       tokens[], tags[], rejection_reason, turn_index,
                       request_surfaces[], response_surfaces[], delta }
     Surface         { label, role?, kind, runs[], block_hash }
     Run             { text, token? }      // token ABSENT => plain run
     TokenRef        { token, value, entity_kind, surface }
     TurnDelta       { prev_turn?, is_first, prev_unavailable, added_surface_hashes[] }
     ConversationMeta{ id, label, turn_count, last_updated_ms, pending_count }
   Surfaces are rendered run-by-run with ZERO client offset arithmetic.
   ============================================================ */

/* ---------- key handling (x-zlauder-key + EventSource ?key=) ---------- */
let key = new URLSearchParams(location.search).get('key')
       || localStorage.getItem('zlauderKey') || '';
if (key) { localStorage.setItem('zlauderKey', key); history.replaceState(null, '', location.pathname); }
if (!key) { key = (prompt('x-zlauder-key') || '').trim(); if (key) localStorage.setItem('zlauderKey', key); }

const hdr = { 'x-zlauder-key': key, 'content-type': 'application/json' };
function api(path, opts = {}) { opts.headers = { ...(opts.headers || {}), ...hdr }; return fetch(path, opts); }

/* ---------- state ---------- */
let records = [];
let conversations = [];
let selectedId = null;
let channelFilter = null;
let channelQuery = '';
let decisionFilter = 'pending';   // live | pending | rejected | backpressure | all
let decisionFilterUserSet = false; // true once the operator picks a filter (stops mode-driven default)
let trafficQuery = '';
let revealValues = localStorage.getItem('zlRevealValues') === '1';
let approvalTimeoutMs = 300000;   // overwritten by snapshot.approval_timeout_secs

/* ---------- ledger view state ---------- */
let view = 'ledger';                 // 'ledger' (default, always) | 'inspector'
let sessionTokens = [];              // snapshot.session_tokens (durable, session-scoped)
let ledgerAllow = { exact: [], exact_ci: [] };  // GET /zlauder/config .config.allow_list
let ledgerCustomRules = [];          // GET /zlauder/monitor/custom-mask
const peeked = new Set();            // row keys currently peeked (local plaintext, anti shoulder-surf)
const MAX_SESSION_TOKENS = 5000;     // mirror the server cap so live SSE augmentation stays bounded
// The four common-word defaults are always re-seeded; only NON-default allow-list
// entries are operator-configured / reveal-created "passing plaintext".
const DEFAULT_ALLOW = { exact: new Set(['Anthropic', 'Claude', '127.0.0.1']), exact_ci: new Set(['localhost']) };

const $ = id => document.getElementById(id);

/* ---------- decision vocabulary ---------- */
const DECISION = {
  pending:               { label: 'Pending',        cls: 'st-pending',  icon: '●' },
  approved:              { label: 'Approved',        cls: 'st-good',     icon: '✓' },
  auto_accepted:         { label: 'Auto-accepted',   cls: 'st-good',     icon: '✓' },
  in_flight:             { label: 'In flight',       cls: 'st-live',     icon: '◴' },
  completed:             { label: 'Completed',       cls: 'st-good',     icon: '✓' },
  rejected:             { label: 'Rejected',         cls: 'st-bad',      icon: '✕' },
  timed_out:            { label: 'Timed out',        cls: 'st-amber',    icon: '⧖' },
  backpressure_rejected:{ label: 'Blocked — queue full', cls: 'st-amber', icon: '⌀' },
  upstream_error:       { label: 'Upstream error',   cls: 'st-amber',    icon: '⚠' },
  aborted:              { label: 'Aborted',         cls: 'st-amber',    icon: '⊘' },
};
function decisionInfo(d) {
  return DECISION[d] || { label: String(d || '').replace(/_/g, ' '), cls: 'st-bad', icon: '•' };
}

/* ---------- utils ---------- */
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
function attr(s) { return esc(s).replace(/\n/g, '&#10;'); }
function ago(ms) {
  if (!ms) return '';
  const d = Date.now() - Number(ms);
  if (d < 1500) return 'now';
  const s = Math.floor(d / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm';
  const h = Math.floor(m / 60);
  if (h < 24) return h + 'h';
  return Math.floor(h / 24) + 'd';
}
function toast(msg, kind) {
  const tpl = $('tpl-toast').content.cloneNode(true);
  const el = tpl.querySelector('.toast');
  if (kind) el.classList.add(kind);
  el.querySelector('.toast-msg').innerHTML = msg;
  $('toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 320); }, 3200);
}

/* ---------- timeout / in-flight helpers ---------- */
function remainingMs(r) {
  if (r.decision !== 'pending') return null;
  return approvalTimeoutMs - (Date.now() - Number(r.started_ms));
}
/* Elapsed since the request was released upstream (live streaming timer). */
function elapsedMs(r) {
  if (r.decision !== 'in_flight') return null;
  return Date.now() - Number(r.dispatched_ms || r.started_ms);
}
function fmtClock(ms) {
  if (ms == null) return '';
  const s = Math.max(0, Math.ceil(ms / 1000));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}
function clockClass(ms) {
  if (ms == null) return '';
  if (ms <= 30000) return 'crit';
  if (ms <= 60000) return 'warn';
  return '';
}

/* ---------- entity-kind rollup ---------- */
function rollup(tokens) {
  const counts = {};
  for (const t of (tokens || [])) {
    const k = t.entity_kind || 'UNKNOWN';
    counts[k] = (counts[k] || 0) + 1;
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1]);
}
function rollupChips(tokens, cls) {
  const r = rollup(tokens);
  if (!r.length) return '';
  return r.map(([k, n]) =>
    `<span class="kind-chip ${cls || ''}">${n}× ${esc(k)}</span>`).join('');
}

/* ---------- risk: non-empty surfaces but nothing masked ---------- */
function isNothingMaskedRisk(r) {
  const surfaces = r.request_surfaces || [];
  if (!surfaces.length) return false;
  const tokenRuns = surfaces.some(s => (s.runs || []).some(run => run.token));
  return !tokenRuns;
}

/* ============================================================
   SURFACE / RUN RENDERING  (zero offset arithmetic)
   A run with a `token` is a masked occurrence -> chip that reveals
   the hidden canonical value. A run without `token` is plain text.
   Concatenated run.text reproduces the surface byte-for-byte.
   ============================================================ */
function renderRuns(runs) {
  return (runs || []).map(run => {
    if (run.token) {
      const t = run.token;
      const reveal = `${t.entity_kind}\n${t.value}` + (t.surface ? `\n(${t.surface})` : '');
      const aria = `masked ${t.entity_kind}: ${t.value}`;
      const shown = revealValues ? esc(t.value) : esc(run.text);
      const cls = revealValues ? 'mark revealed' : 'mark';
      return `<span class="${cls}" tabindex="0" role="button" aria-label="${attr(aria)}" data-reveal="${attr(reveal)}">${shown}</span>`;
    }
    return esc(run.text);
  }).join('');
}

function renderSurface(s, addedSet) {
  const isNew = addedSet && addedSet.has(s.block_hash);
  const kindClass = 'kind-' + s.kind;
  const role = s.role ? ` &middot; ${esc(s.role)}` : '';
  return `<div class="surface ${isNew ? 'is-new' : ''}">`
    + `<div class="surface-head">`
    +   `<span class="kind-tag ${kindClass}">${esc(s.kind)}</span>`
    +   `<span class="surface-label">${esc(s.label)}${role}</span>`
    +   (isNew ? `<span class="new-flag">NEW</span>` : '')
    +   `<span class="surface-hash" title="block hash ${esc(s.block_hash)}">${esc(s.block_hash)}</span>`
    + `</div>`
    + `<pre class="payload">${renderRuns(s.runs)}</pre>`
  + `</div>`;
}

/* ============================================================
   NEW PLAINTEXT THIS TURN
   For a held request, the operator's job is to read the actual values
   about to leave the machine. List handle -> value -> kind for every
   token whose run lives in a surface flagged new this turn (or, when
   the delta is unavailable / first turn, for all tokens).
   ============================================================ */
function newPlaintext(r) {
  const delta = r.delta || {};
  const surfaces = r.request_surfaces || [];
  let scope;
  if (delta.is_first || delta.prev_unavailable) {
    scope = surfaces;
  } else {
    const added = new Set(delta.added_surface_hashes || []);
    scope = surfaces.filter(s => added.has(s.block_hash));
  }
  const seen = new Set();
  const out = [];
  for (const s of scope) {
    for (const run of (s.runs || [])) {
      if (!run.token) continue;
      const t = run.token;
      const dedup = `${t.token} ${t.value}`;
      if (seen.has(dedup)) continue;
      seen.add(dedup);
      out.push(t);
    }
  }
  return out;
}

/* ============================================================
   DELTA SPOTLIGHT  (the heart of the review)
   ============================================================ */
function renderSpotlight(r) {
  const delta = r.delta || {};
  const addedSet = new Set(delta.added_surface_hashes || []);
  const surfaces = r.request_surfaces || [];
  const newSurfaces = surfaces.filter(s => addedSet.has(s.block_hash));
  const nothingMasked = isNothingMaskedRisk(r);

  // Highest-priority risk: text surfaces exist this turn but zero are masked.
  if (nothingMasked) {
    const scope = (delta.is_first || delta.prev_unavailable) ? surfaces
                : (newSurfaces.length ? newSurfaces : surfaces);
    return `<div class="spotlight warn">`
      + `<div class="spotlight-head">`
      +   `<span class="spotlight-icon">&#9888;</span>`
      +   `<span class="spotlight-title">NOTHING MASKED HERE</span>`
      +   `<span class="spotlight-sub">eyeball the raw text for unmasked PII</span>`
      + `</div>`
      + `<div class="spotlight-body">`
      +   scope.map(s => renderSurface(s, addedSet)).join('')
      + `</div></div>`;
  }

  if (delta.is_first) {
    const allNew = new Set(surfaces.map(s => s.block_hash));
    // The whole transcript is genuinely new, but dumping every surface here is
    // noisy and duplicates the FULL MASKED REQUEST panel below. Show the first
    // few; the rest stay one click away.
    const CAP = 6;
    const head = surfaces.slice(0, CAP);
    const extra = surfaces.length - head.length;
    return `<div class="spotlight">`
      + `<div class="spotlight-head">`
      +   `<span class="spotlight-icon">&#9650;</span>`
      +   `<span class="spotlight-title">FIRST CONTACT</span>`
      +   `<span class="spotlight-sub">entire conversation is new &mdash; ${surfaces.length} surface(s)</span>`
      + `</div>`
      + `<div class="spotlight-body">`
      +   (surfaces.length ? head.map(s => renderSurface(s, allNew)).join('')
                            : `<div class="empty-note">No recognized text surfaces in this request.</div>`)
      +   (extra > 0 ? `<div class="empty-note">+${extra} more surface(s) — see FULL MASKED REQUEST below.</div>` : '')
      + `</div></div>`;
  }

  if (delta.prev_unavailable) {
    return `<div class="spotlight warn">`
      + `<div class="spotlight-head">`
      +   `<span class="spotlight-icon">&#9888;</span>`
      +   `<span class="spotlight-title">PREVIOUS TURN EVICTED</span>`
      +   `<span class="spotlight-sub">cannot compute delta vs turn ${delta.prev_turn ?? '-'} &mdash; audit full request</span>`
      + `</div>`
      + `<div class="spotlight-body">`
      +   (surfaces.length ? surfaces.map(s => renderSurface(s, null)).join('')
                            : `<div class="empty-note">No recognized text surfaces in this request.</div>`)
      + `</div></div>`;
  }

  if (!newSurfaces.length) {
    return `<div class="spotlight calm">`
      + `<div class="spotlight-head">`
      +   `<span class="spotlight-icon">&#9679;</span>`
      +   `<span class="spotlight-title">NO NEW EXPOSURE</span>`
      +   `<span class="spotlight-sub">turn ${r.turn_index} resends prior context (prev turn ${delta.prev_turn ?? '-'})</span>`
      + `</div>`
      + `<div class="spotlight-body"><div class="empty-note">`
      +   `Nothing new is exposed this turn. Expand the full request below to audit resent context.`
      + `</div></div></div>`;
  }

  return `<div class="spotlight">`
    + `<div class="spotlight-head">`
    +   `<span class="spotlight-icon">&#9650;</span>`
    +   `<span class="spotlight-title">DELTA &middot; ${newSurfaces.length} NEW SURFACE${newSurfaces.length === 1 ? '' : 'S'}</span>`
    +   `<span class="spotlight-sub">new this turn vs turn ${delta.prev_turn ?? '-'}</span>`
    + `</div>`
    + `<div class="spotlight-body">`
    +   newSurfaces.map(s => renderSurface(s, addedSet)).join('')
    + `</div></div>`;
}

/* ============================================================
   FULL MASKED REQUEST / RESPONSE  (legacy preview + spans)
   ============================================================ */
function renderSpanned(preview, spans) {
  if (preview == null) return '';
  const text = String(preview);
  spans = (spans || []).slice().sort((a, b) => a.start - b.start);
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const bytes = enc.encode(text);
  let out = '', cursor = 0;
  for (const sp of spans) {
    if (sp.start < cursor || sp.start > bytes.length) continue;
    out += esc(dec.decode(bytes.subarray(cursor, sp.start)));
    const handle = dec.decode(bytes.subarray(sp.start, Math.min(sp.end, bytes.length)));
    const reveal = `${esc(sp.entity_kind)}` + (sp.surface ? `\n(${esc(sp.surface)})` : '');
    out += `<span class="mark" tabindex="0" role="button" aria-label="${attr('masked ' + sp.entity_kind)}" data-reveal="${attr(reveal)}">${esc(handle)}</span>`;
    cursor = sp.end;
  }
  out += esc(dec.decode(bytes.subarray(cursor)));
  return out;
}

/* ============================================================
   REVIEW PANE
   ============================================================ */
const REJECT_PRESETS = ['unmasked PII', 'wrong recipient', 'policy'];

function zeroState() {
  const pendingCount = records.filter(r => r.decision === 'pending').length;
  if (pendingCount > 0) {
    return `<div class="placeholder">`
      + `<span class="placeholder-glyph warn">&#9888;</span>`
      + `<p>${pendingCount} HELD &mdash; SELECT TO REVIEW</p>`
      + `<small>Requests are paused before egress under a ${Math.round(approvalTimeoutMs / 1000)}s clock. Pick a held intercept in the queue.</small>`
      + `</div>`;
  }
  if (!records.length) {
    return `<div class="placeholder">`
      + `<span class="placeholder-glyph">&#9678;</span>`
      + `<p>NO TRAFFIC YET</p>`
      + `<small>Drive an LLM request through the proxy; held requests land here for review.</small>`
      + `</div>`;
  }
  return `<div class="placeholder">`
    + `<span class="placeholder-glyph good">&#9679;</span>`
    + `<p>QUEUE CLEAR</p>`
    + `<small>Nothing is held right now. Select any intercept to audit what plaintext it sent.</small>`
    + `</div>`;
}

function renderReview() {
  const r = records.find(x => x.id === selectedId);
  const d = $('detail');
  if (!r) { d.innerHTML = zeroState(); return; }

  const tokens = r.tokens || [];
  const tags = r.tags || [];
  const pending = r.decision === 'pending';
  const di = decisionInfo(r.decision);
  const rem = remainingMs(r);

  const rollHead = tokens.length ? `<div class="rh-rollup">${rollupChips(tokens)}</div>` : '';

  const head = `<div class="review-head">`
    + `<div><div class="rh-id">TURN ${r.turn_index}`
    +   `<small title="${esc(r.id)}">${esc(r.method)} ${esc(r.endpoint)} &middot; ${esc(r.id)}</small></div>${rollHead}</div>`
    + `<div class="rh-spacer"></div>`
    + `<div class="rh-controls">`
    +   `<label class="reveal-toggle"><input type="checkbox" id="revealToggle" ${revealValues ? 'checked' : ''}> reveal values</label>`
    +   `<div class="rh-tags">${tags.map(t =>
          `<span class="rh-tag">${esc(t)}<button class="tag-x" data-act="untag" data-id="${esc(r.id)}" data-tag="${attr(t)}" aria-label="remove tag ${attr(t)}">&times;</button></span>`).join('')}</div>`
    + `</div>`
  + `</div>`;

  const countdown = pending
    ? `<span class="countdown ${clockClass(rem)}" data-countdown="${esc(r.id)}" title="server hold timeout">&#9201; ${fmtClock(rem)}</span>`
    : '';

  const verdict = `<div class="verdict-bar">`
    + `<span class="verdict ${di.cls}">${di.icon} ${esc(di.label)}</span>`
    + countdown
    + (r.response_status ? `<span class="surface-label">HTTP ${r.response_status}</span>` : '')
    + (r.rejection_reason ? `<span class="reason-tag" title="${attr(r.rejection_reason)}">${esc(r.rejection_reason)}</span>` : '')
    + (pending
        ? `<div class="action-group">`
          + `<div class="reject-cluster">`
          +   `<input class="reject-reason" id="rejectReason" placeholder="reject reason&hellip;" autocomplete="off">`
          +   `<div class="reject-presets">`
          +     REJECT_PRESETS.map(p => `<button class="preset-chip" data-act="preset" data-reason="${attr(p)}">${esc(p)}</button>`).join('')
          +   `</div>`
          + `</div>`
          + `<button class="btn danger" data-act="reject" data-id="${esc(r.id)}" title="hotkey R">REJECT</button>`
          + `<button class="btn primary" data-act="approve" data-id="${esc(r.id)}" title="hotkey A">APPROVE</button>`
          + `</div>`
        : '')
  + `</div>`;

  // Always-visible new plaintext for a held request: the secret, not the bookkeeping.
  let plaintextBlock = '';
  if (pending) {
    const np = newPlaintext(r);
    if (np.length) {
      plaintextBlock = `<div class="newplain">`
        + `<div class="newplain-head"><span class="newplain-icon">&#9888;</span>`
        +   `<span class="newplain-title">NEW PLAINTEXT THIS TURN</span>`
        +   `<span class="newplain-sub">${np.length} value${np.length === 1 ? '' : 's'} about to leave this machine</span></div>`
        + `<div class="newplain-grid">`
        +   np.map(t =>
              `<div class="newplain-row">`
              + `<span class="np-handle">${esc(t.token)}</span>`
              + `<span class="np-arrow">&rarr;</span>`
              + `<span class="np-value">${esc(t.value)}</span>`
              + `<span class="np-kind">${esc(t.entity_kind)}</span>`
              + `</div>`).join('')
        + `</div></div>`;
    } else if (!isNothingMaskedRisk(r)) {
      plaintextBlock = `<div class="newplain empty">`
        + `<div class="newplain-head"><span class="newplain-icon">&#9679;</span>`
        +   `<span class="newplain-title">NO NEW PLAINTEXT</span>`
        +   `<span class="newplain-sub">this turn masks nothing new vs the prior turn</span></div>`
        + `</div>`;
    }
  }

  const spotlight = renderSpotlight(r);

  const tokenLedger = `<details class="panel"${pending ? ' open' : ''}>`
    + `<summary><span class="panel-title">TOKEN LEDGER</span>`
    +   `<span class="panel-rollup">${rollupChips(tokens)}</span>`
    +   `<span class="panel-count">${tokens.length}</span></summary>`
    + `<div class="panel-body"><div class="token-grid">`
    +   (tokens.length ? tokens.map(t =>
          `<div class="token-row">`
          + `<span class="token-handle">${esc(t.token)}</span>`
          + `<span class="token-value"><span class="token-arrow">&rarr;</span> ${esc(t.value)}</span>`
          + `<span class="token-kind">${esc(t.entity_kind)}</span>`
          + `</div>`).join('')
        : `<div class="empty-note">No tokens masked in this request.</div>`)
    + `</div></div></details>`;

  const reqSurfaces = r.request_surfaces || [];
  const fullRequest = `<details class="panel"${pending ? ' open' : ''}>`
    + `<summary><span class="panel-title">FULL MASKED REQUEST</span><span class="panel-count">${reqSurfaces.length} surface(s)</span></summary>`
    + `<div class="panel-body">`
    +   (reqSurfaces.length
          ? reqSurfaces.map(s => renderSurface(s, new Set(r.delta && r.delta.added_surface_hashes))).join('')
          : `<div class="empty-note">No structured surfaces. Raw preview:</div><pre class="payload">${renderSpanned(r.request_preview, r.request_spans)}</pre>`)
    + `</div></details>`;

  const respSurfaces = r.response_surfaces || [];
  const respHasTokenRun = respSurfaces.some(s => (s.runs || []).some(run => run.token));
  const hasResp = r.response_preview != null || respSurfaces.length;
  const fullResponse = hasResp ? `<details class="panel">`
    + `<summary><span class="panel-title">RESPONSE</span><span class="panel-count">${r.response_status ? 'HTTP ' + r.response_status : ''}</span></summary>`
    + `<div class="panel-body">`
    +   (respHasTokenRun
          ? respSurfaces.map(s => renderSurface(s, null)).join('')
          : `<pre class="payload">${renderSpanned(r.response_preview, r.response_spans)}</pre>`)
    + `</div></details>`
    : '';

  const tagComposer = `<details class="panel">`
    + `<summary><span class="panel-title">ANNOTATE</span></summary>`
    + `<div class="panel-body"><div class="tag-composer">`
    +   `<input id="tagInput" placeholder="add tag to this intercept&hellip;" autocomplete="off">`
    +   `<button class="btn ghost" data-act="tag" data-id="${esc(r.id)}">TAG</button>`
    + `</div></div></details>`;

  d.innerHTML = head + verdict + plaintextBlock + spotlight + tokenLedger + fullRequest + fullResponse + tagComposer;
}

/* ============================================================
   CHANNELS (conversations) + TRAFFIC (records)
   ============================================================ */
function renderChannels() {
  const q = channelQuery.toLowerCase();
  const list = conversations.filter(c =>
    !q || (c.label || '').toLowerCase().includes(q) || (c.id || '').toLowerCase().includes(q));
  $('convoCount').textContent = conversations.length;
  $('sessions').innerHTML = list.length ? list.map(c =>
    `<div class="convo ${channelFilter === c.id ? 'active' : ''}" data-channel="${esc(c.id)}">`
    + `<div class="convo-top"><span class="convo-label" title="${esc(c.id)}">${esc(c.label)}</span></div>`
    + `<div class="convo-meta">`
    +   `<span class="turn-pip">${c.turn_count} turn${c.turn_count === 1 ? '' : 's'}</span>`
    +   (c.pending_count ? `<span class="pending-badge">${c.pending_count} HOLD</span>` : '')
    +   `<span class="ago">${ago(c.last_updated_ms)}</span>`
    + `</div></div>`
  ).join('') : `<div class="empty-note" style="padding:14px">No conversations${channelQuery ? ' match.' : ' yet.'}</div>`;
}

const DECISION_FILTERS = {
  // Live = active + recent successful traffic; hides terminal error/abort noise.
  live:         r => !['rejected', 'timed_out', 'backpressure_rejected', 'aborted', 'upstream_error'].includes(r.decision),
  pending:      r => r.decision === 'pending',
  rejected:     r => r.decision === 'rejected',
  backpressure: r => r.decision === 'backpressure_rejected',
  all:          () => true,
};

function trafficMatches(r) {
  if (channelFilter && r.conversation_id !== channelFilter) return false;
  if (!(DECISION_FILTERS[decisionFilter] || DECISION_FILTERS.all)(r)) return false;
  if (trafficQuery) {
    const q = trafficQuery.toLowerCase();
    const hay = [r.id, r.endpoint, ...(r.tags || []),
                 ...(r.tokens || []).map(t => t.entity_kind)].join(' ').toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function renderFilterCounts() {
  const within = records.filter(r => !channelFilter || r.conversation_id === channelFilter);
  const set = (id, n) => { const el = $(id); if (el) el.textContent = n; };
  set('fcLive', within.filter(DECISION_FILTERS.live).length);
  set('fcPending', within.filter(DECISION_FILTERS.pending).length);
  set('fcRejected', within.filter(DECISION_FILTERS.rejected).length);
  set('fcBackpressure', within.filter(DECISION_FILTERS.backpressure).length);
  set('fcAll', within.length);
  document.querySelectorAll('.df-chip').forEach(el =>
    el.classList.toggle('active', el.dataset.filter === decisionFilter));
}

function renderTraffic(flashId) {
  // Active traffic floats up: pending first (oldest = closest to timeout), then
  // in-flight, then everything else newest-first.
  const rank = r => r.decision === 'pending' ? 0 : r.decision === 'in_flight' ? 1 : 2;
  const visible = records.filter(trafficMatches).slice().sort((a, b) => {
    const ra = rank(a), rb = rank(b);
    if (ra !== rb) return ra - rb;
    if (ra === 0) return Number(a.started_ms) - Number(b.started_ms); // oldest pending first
    return Number(b.started_ms) - Number(a.started_ms);              // newest first otherwise
  });
  const title = channelFilter
    ? (conversations.find(c => c.id === channelFilter)?.label || 'CONVERSATION')
    : 'TRAFFIC';
  $('recordsTitle').textContent = title.toUpperCase();
  $('clearFilter').hidden = !channelFilter;
  renderFilterCounts();

  $('records').innerHTML = visible.length ? visible.map(r => {
    const tc = (r.tokens || []).length;
    const di = decisionInfo(r.decision);
    const risk = isNothingMaskedRisk(r);
    const newCount = (r.delta && !r.delta.is_first) ? (r.delta.added_surface_hashes || []).length : -1;
    const pending = r.decision === 'pending';
    const inflight = r.decision === 'in_flight';
    const rem = remainingMs(r);
    const ela = elapsedMs(r);
    const roll = rollup(r.tokens).slice(0, 3)
      .map(([k, n]) => `<span class="rec-kind">${n}×${esc(k)}</span>`).join('');
    return `<div class="rec ${pending ? 'pending' : ''} ${inflight ? 'inflight' : ''} ${risk ? 'risk' : ''} ${selectedId === r.id ? 'active' : ''} ${flashId === r.id ? 'flash' : ''}" data-rec="${esc(r.id)}">`
      + `<div class="rec-top">`
      +   `<span class="rec-turn">T${r.turn_index}</span>`
      +   `<span class="rec-endpoint">${esc(r.endpoint)}</span>`
      +   (pending ? `<span class="rec-clock ${clockClass(rem)}" data-countdown="${esc(r.id)}">&#9201; ${fmtClock(rem)}</span>` : '')
      +   (inflight ? `<span class="rec-clock live" data-elapsed="${esc(r.id)}">&#9201; ${fmtClock(ela)} streaming</span>` : '')
      +   (r.delta && r.delta.is_first ? `<span class="new-flag">FIRST</span>`
            : (r.delta && r.delta.prev_unavailable ? `<span class="new-flag warn-flag">?</span>`
            : (newCount > 0 ? `<span class="new-flag">+${newCount}</span>` : '')))
      + `</div>`
      + `<div class="rec-meta">`
      +   `<span class="status-tag ${di.cls}">${esc(di.label)}</span>`
      +   (risk ? `<span class="risk-tag" title="text surfaces present but nothing masked">UNMASKED?</span>`
              : `<span class="tok-count ${tc ? '' : 'zero'}">${tc} tok</span>`)
      +   `<span class="ago">${ago(r.started_ms)}</span>`
      + `</div>`
      + (roll ? `<div class="rec-kinds">${roll}</div>` : '')
    + `</div>`;
  }).join('') : `<div class="empty-note" style="padding:14px">No ${decisionFilter === 'all' ? '' : decisionFilter + ' '}traffic${channelFilter ? ' in this conversation.' : '.'}</div>`;
}

/* ---------- header ---------- */
function renderHeader(snap) {
  if (snap) {
    $('mode').value = snap.mode;
    const max = snap.max_pending_approvals || 0;
    const pend = snap.pending_count || 0;
    const capInput = $('queueCap');
    if (capInput && document.activeElement !== capInput) capInput.value = max;
    $('queuePend').textContent = pend;
    const pct = max ? Math.min(100, (pend / max) * 100) : (pend ? 100 : 0);
    $('queueFill').style.width = pct + '%';
    const hot = max > 0 && pend >= max;
    $('queueMeter').classList.toggle('hot', hot);
    $('backpressureNote').hidden = !hot;
  }
}

function render(flashId) {
  renderChannels();
  renderTraffic(flashId);
  renderReview();
  renderLedger();
  renderViewState();
}

/* ============================================================
   VIEW TABS  —  Ledger (default) vs Inspector
   ============================================================ */
function renderViewState() {
  const pending = records.filter(r => r.decision === 'pending').length;
  $('viewLedger').hidden = view !== 'ledger';
  $('viewInspector').hidden = view !== 'inspector';
  $('tabLedger').classList.toggle('active', view === 'ledger');
  $('tabInspector').classList.toggle('active', view === 'inspector');
  const badge = $('tabInspectorBadge');
  badge.textContent = pending;
  badge.hidden = pending === 0;
}
function setView(v) { view = v; renderViewState(); }
$('tabLedger').addEventListener('click', () => setView('ledger'));
$('tabInspector').addEventListener('click', () => setView('inspector'));

/* ============================================================
   LEDGER  —  the secrets-first default view.
   Three groups (custom first), values masked by default with a per-row local
   PEEK (anti shoulder-surf; never sent anywhere), plus a holds strip that keeps
   the approve/reject loop reachable without leaving the ledger.

   Two distinct "reveals" (do not conflate):
     - PEEK   : show plaintext in THIS browser only. Pure client state (`peeked`).
     - REVEAL TO MODEL : allow-list the value so it egresses UNMASKED upstream;
                durable, privacy-reducing → confirm first. Server-side.
   Auto-detected rows whose class is non-peekable (reserved for the secrets engine)
   render locked and cannot be revealed — the value is never in the snapshot.
   ============================================================ */

/* A value chip: masked by default; click peeks the plaintext locally. A non-peekable
   (secret-class) row renders a static lock — no value, no peek. */
function peekChip(rowKey, value, peekable) {
  if (peekable === false) {
    return `<span class="lv-val locked" title="secret — value withheld from the UI">••••••</span>`;
  }
  const on = peeked.has(rowKey);
  return `<span class="lv-val peek ${on ? 'on' : ''}" data-peek="${attr(rowKey)}" tabindex="0" role="button"`
    + ` aria-label="${on ? 'hide value' : 'reveal value locally'}"`
    + ` title="${on ? 'click to hide' : 'click to reveal locally — not sent anywhere'}">`
    + `${on ? esc(value) : '••••••'}</span>`;
}

function renderLedger() {
  // ---- holds strip (keeps approve/reject reachable from the ledger) ----
  const holds = records.filter(r => r.decision === 'pending')
    .slice().sort((a, b) => Number(a.started_ms) - Number(b.started_ms));
  $('ledgerHoldsWrap').hidden = holds.length === 0;
  $('ledgerHolds').innerHTML = holds.map(r => {
    const rem = remainingMs(r);
    return `<div class="lhold" data-hold-select="${esc(r.id)}" title="open in inspector">`
      + `<span class="lhold-turn">T${r.turn_index}</span>`
      + `<span class="lhold-ep">${esc(r.endpoint)}</span>`
      + `<span class="lhold-clock ${clockClass(rem)}" data-countdown="${esc(r.id)}">⏱ ${fmtClock(rem)}</span>`
      + `<span class="lhold-tok">${(r.tokens || []).length} tok</span>`
      + `<button class="btn danger sm" data-act="reject" data-id="${esc(r.id)}">REJECT</button>`
      + `<button class="btn primary sm" data-act="approve" data-id="${esc(r.id)}">APPROVE</button>`
      + `</div>`;
  }).join('');

  // ---- passing plaintext: non-default allow-list entries ----
  const allowExact = (ledgerAllow.exact || []).filter(v => !DEFAULT_ALLOW.exact.has(v));
  const allowCi = (ledgerAllow.exact_ci || []).filter(v => !DEFAULT_ALLOW.exact_ci.has(v));
  const plainRows = [...allowExact.map(v => ({ v, ci: false })), ...allowCi.map(v => ({ v, ci: true }))];
  $('ledgerRevealedCount').textContent = plainRows.length;
  $('ledgerRevealed').innerHTML = plainRows.length ? plainRows.map(({ v, ci }) => {
    const key = 'al:' + (ci ? 'ci:' : '') + v;
    return `<div class="lrow plain">`
      + peekChip(key, v, true)
      + `<span class="lrow-tag">${ci ? 'ci' : 'exact'}</span>`
      + `<button class="btn ghost sm" data-lact="remask" data-value="${attr(v)}" title="resume masking this value">RE-MASK</button>`
      + `</div>`;
  }).join('') : `<div class="empty-note">Nothing passes plaintext. Reveal a value below to send it unmasked.</div>`;

  // Values already shown as plaintext / as a custom rule are not repeated under AUTO.
  const allowedSet = new Set([
    ...allowExact, ...allowExact.map(v => v.toLowerCase()), ...allowCi.map(v => v.toLowerCase()),
  ]);
  const customSet = new Set(ledgerCustomRules.map(c => c.pattern));

  // ---- custom keyphrases ----
  $('ledgerCustomCount').textContent = ledgerCustomRules.length;
  $('ledgerCustom').innerHTML = ledgerCustomRules.length ? ledgerCustomRules.map(c => {
    const key = 'cm:' + c.pattern;
    return `<div class="lrow">`
      + peekChip(key, c.pattern, true)
      + `<span class="lrow-kind">${esc(c.entity_type)}</span>`
      + `<span class="lrow-tag">${c.case_sensitive ? 'CS' : 'ci'}</span>`
      + `<button class="btn ghost sm warn" data-lact="reveal" data-value="${attr(c.pattern)}" data-pattern="${attr(c.pattern)}" data-entity="${attr(c.entity_type)}">REVEAL TO MODEL</button>`
      + `<button class="btn ghost sm" data-lact="rm-custom" data-pattern="${attr(c.pattern)}" data-entity="${attr(c.entity_type)}">REMOVE</button>`
      + `</div>`;
  }).join('') : `<div class="empty-note">No custom keyphrases. Add one above, or select text in a request (inspector).</div>`;

  // ---- auto-detected (durable session_tokens, dedup vs above) ----
  const seen = new Set();
  const autoRows = sessionTokens.filter(t => {
    const val = t.value || '';
    if (val && (allowedSet.has(val) || allowedSet.has(val.toLowerCase()))) return false;
    if (val && customSet.has(val)) return false;
    if (seen.has(t.token)) return false;
    seen.add(t.token); return true;
  });
  $('ledgerTokensCount').textContent = autoRows.length;
  $('ledgerTokens').innerHTML = autoRows.length ? autoRows.map(t => {
    const key = 'tok:' + t.token;
    const canReveal = t.peekable !== false && !!t.value;
    return `<div class="lrow">`
      + `<span class="lrow-handle">${esc(t.token)}</span>`
      + peekChip(key, t.value, t.peekable)
      + `<span class="lrow-kind">${esc(t.entity_kind)}</span>`
      + (t.count > 1 ? `<span class="lrow-tag">×${t.count}</span>` : '')
      + (canReveal ? `<button class="btn ghost sm warn" data-lact="reveal" data-value="${attr(t.value)}">REVEAL TO MODEL</button>` : '')
      + `</div>`;
  }).join('') : `<div class="empty-note">No PII auto-detected yet this session.</div>`;
}

/* ---- ledger sources: allow-list + custom rules (fetched once + after edits) ---- */
function applyLedgerConfig(wire) { if (wire && wire.allow_list) ledgerAllow = wire.allow_list; }
function refreshLedgerSources() {
  const a = api('/zlauder/config').then(r => r.ok ? r.json() : null)
    .then(s => { if (s && s.config && s.config.allow_list) ledgerAllow = s.config.allow_list; }).catch(() => {});
  const b = api('/zlauder/monitor/custom-mask').then(r => r.ok ? r.json() : null)
    .then(d => { if (d) ledgerCustomRules = d.custom_replacements || []; }).catch(() => {});
  return Promise.all([a, b]).then(renderLedger);
}

/* ---- ledger actions ---- */
function revealToModel(value, pattern, entity) {
  if (!value) return;
  const ok = window.confirm(
    `Reveal to the model?\n\n  ${value}\n\n`
    + `This value will be sent to the model UNMASKED from now on, and the choice is `
    + `persisted to zlauder.local.toml. Note: this does not touch values masked by a `
    + `config regex pattern, nor masking-exempt control/schema keys. You can RE-MASK `
    + `any time from PASSING PLAINTEXT.`
  );
  if (!ok) return;
  const body = { value };
  if (pattern) { body.pattern = pattern; body.entity_type = entity || 'CUSTOM_KEYWORD'; }
  api('/zlauder/monitor/reveal', { method: 'POST', body: JSON.stringify(body) })
    .then(async r => {
      if (!r.ok) { toast('reveal failed', 'bad'); return; }
      let res = {}; try { res = await r.json(); } catch {}
      const note = res.session_only ? ' (live only — persist failed)' : (res.persisted ? ' (persisted)' : '');
      toast(`revealed <b>${esc(value)}</b> to the model${note}`, 'bad');
      applyLedgerConfig(res.config);
      refreshLedgerSources();
      if (!$('policyDrawer').hidden) loadCustomMasks();
    })
    .catch(() => toast('reveal failed', 'bad'));
}
function remaskValue(value) {
  if (!value) return;
  api('/zlauder/monitor/reveal', { method: 'DELETE', body: JSON.stringify({ value }) })
    .then(async r => {
      if (!r.ok) { toast('re-mask failed', 'bad'); return; }
      let res = {}; try { res = await r.json(); } catch {}
      toast(`re-masking <b>${esc(value)}</b>${res.removed_live ? '' : ' (was not allow-listed)'}`, 'good');
      applyLedgerConfig(res.config);
      refreshLedgerSources();
    })
    .catch(() => toast('re-mask failed', 'bad'));
}
function removeCustomRule(pattern, entity_type) {
  api('/zlauder/monitor/custom-mask', { method: 'DELETE', body: JSON.stringify({ pattern, entity_type }) })
    .then(r => r.ok ? r.json() : Promise.reject(new Error('remove failed')))
    .then(res => {
      toast(`removed mask <b>${esc(pattern)}</b>${res.removed_persisted ? ' (live + persisted)' : ' (live only)'}`, 'good');
      refreshLedgerSources();
      if (!$('policyDrawer').hidden) loadCustomMasks();
    })
    .catch(() => toast('mask remove failed', 'bad'));
}
function ledgerAdd() {
  const pat = ($('ledgerAddInput').value || '').trim();
  if (!pat) return;
  const entity = ($('ledgerAddEntity').value || '').trim() || 'CUSTOM_KEYWORD';
  const caseSensitive = $('ledgerAddCase').checked;
  api('/zlauder/monitor/custom-mask', { method: 'POST', body: JSON.stringify({ pattern: pat, entity_type: entity, case_sensitive: caseSensitive }) })
    .then(async r => {
      if (!r.ok) { toast('keyphrase rejected', 'bad'); return; }
      let res = {}; try { res = await r.json(); } catch {}
      const note = res.session_only ? ' (session-only — lost on reload)' : (res.persisted ? ' (persisted)' : '');
      toast(`masking <b>${esc(pat)}</b>${note}`, 'good');
      $('ledgerAddInput').value = ''; $('ledgerAddEntity').value = ''; $('ledgerAddCase').checked = false;
      refreshLedgerSources();
      if (!$('policyDrawer').hidden) loadCustomMasks();
    })
    .catch(() => toast('keyphrase add failed', 'bad'));
}
$('ledgerAddGo').addEventListener('click', ledgerAdd);
$('ledgerAddInput').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); ledgerAdd(); } });
$('ledgerAddEntity').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); ledgerAdd(); } });

/* ledger-local delegation: peek toggle, hold-select, reveal/remask/remove */
$('viewLedger').addEventListener('click', e => {
  const peek = e.target.closest('[data-peek]');
  if (peek) {
    const k = peek.dataset.peek;
    if (peeked.has(k)) peeked.delete(k); else peeked.add(k);
    renderLedger();
    return;
  }
  const la = e.target.closest('[data-lact]');
  if (la) {
    const v = la.dataset.value || '';
    if (la.dataset.lact === 'reveal') revealToModel(v, la.dataset.pattern || null, la.dataset.entity || null);
    else if (la.dataset.lact === 'remask') remaskValue(v);
    else if (la.dataset.lact === 'rm-custom') removeCustomRule(la.dataset.pattern, la.dataset.entity);
    return;
  }
  // Clicking a hold row body (not its action buttons) opens it in the inspector.
  const hold = e.target.closest('[data-hold-select]');
  if (hold && !e.target.closest('[data-act]')) {
    selectedId = hold.dataset.holdSelect;
    setView('inspector');
    render();
  }
});

/* ============================================================
   AUTO-SELECT: the gatekeeper must land on a held request.
   Oldest pending (closest to timeout) wins; else keep a valid
   selection; else newest record.
   ============================================================ */
function oldestPending() {
  const pend = records.filter(r => r.decision === 'pending');
  if (!pend.length) return null;
  return pend.reduce((a, b) => Number(a.started_ms) <= Number(b.started_ms) ? a : b);
}
function autoSelect() {
  const cur = records.find(r => r.id === selectedId);
  if (cur && cur.decision === 'pending') return;       // keep an active hold
  const op = oldestPending();
  if (op) { selectedId = op.id; return; }
  if (!cur) selectedId = records.length ? records[0].id : null;
}

/* ============================================================
   ACTIONS
   ============================================================ */
function approve(id) {
  api(`/zlauder/monitor/requests/${id}/approve`, { method: 'POST' })
    .then(r => r.ok ? toast('APPROVED &mdash; released upstream', 'good') : toast('approve failed', 'bad'))
    .then(load);
}
function reject(id, reasonOverride) {
  const reason = (reasonOverride || $('rejectReason')?.value || '').trim() || 'rejected in monitor';
  api(`/zlauder/monitor/requests/${id}/reject`, { method: 'POST', body: JSON.stringify({ reason }) })
    .then(r => r.ok ? toast('REJECTED &mdash; blocked', 'bad') : toast('reject failed', 'bad'))
    .then(load);
}
function tagReq(id) {
  const v = ($('tagInput')?.value || '').trim();
  if (!v) return;
  const existing = records.find(x => x.id === id)?.tags || [];
  if (existing.includes(v)) { toast('tag already present', 'bad'); return; }
  api(`/zlauder/monitor/requests/${id}/tags`, { method: 'POST', body: JSON.stringify({ tags: [...existing, v] }) })
    .then(() => toast('tag added', 'good')).then(load);
}
function untag(id, tag) {
  const existing = records.find(x => x.id === id)?.tags || [];
  api(`/zlauder/monitor/requests/${id}/tags`,
    { method: 'POST', body: JSON.stringify({ tags: existing.filter(t => t !== tag) }) })
    .then(() => toast('tag removed', 'good')).then(load);
}

/* event delegation for all dynamic buttons */
document.addEventListener('click', e => {
  const act = e.target.closest('[data-act]');
  if (act) {
    const id = act.getAttribute('data-id');
    const a = act.dataset.act;
    if (a === 'approve') approve(id);
    else if (a === 'reject') reject(id);
    else if (a === 'tag') tagReq(id);
    else if (a === 'untag') untag(id, act.dataset.tag);
    else if (a === 'preset') { const ri = $('rejectReason'); if (ri) { ri.value = act.dataset.reason; ri.focus(); } }
    return;
  }
  const df = e.target.closest('.df-chip');
  if (df) { decisionFilter = df.dataset.filter; decisionFilterUserSet = true; renderTraffic(); return; }
  const rec = e.target.closest('[data-rec]');
  if (rec) { selectedId = rec.getAttribute('data-rec'); render(); return; }
  const ch = e.target.closest('[data-channel]');
  if (ch) {
    const id = ch.getAttribute('data-channel');
    channelFilter = channelFilter === id ? null : id;
    render(); return;
  }
});

$('clearFilter').addEventListener('click', e => { e.stopPropagation(); channelFilter = null; render(); });
$('convoFilterInput').addEventListener('input', e => { channelQuery = e.target.value; renderChannels(); });
$('trafficSearch').addEventListener('input', e => { trafficQuery = e.target.value; renderTraffic(); });

// Header queue meter clicks through to the pending view.
$('queueMeter').addEventListener('click', e => {
  if (e.target.closest('#queueCap')) return;
  channelFilter = null; decisionFilter = 'pending';
  const op = oldestPending(); if (op) selectedId = op.id;
  render();
});

// reveal-values toggle (delegated; lives inside the review pane)
document.addEventListener('change', e => {
  if (e.target.id === 'revealToggle') {
    revealValues = e.target.checked;
    localStorage.setItem('zlRevealValues', revealValues ? '1' : '0');
    renderReview();
  }
});

// POSTURE auto-applies on change — no SET button. The cap input still commits on
// change / Enter (both call saveMode, which reads the current dropdown + cap).
$('mode').addEventListener('change', saveMode);
$('queueCap').addEventListener('change', saveMode);
$('queueCap').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); saveMode(); } });
function saveMode() {
  const body = { mode: $('mode').value };
  const cap = parseInt($('queueCap').value, 10);
  if (Number.isFinite(cap) && cap >= 0) body.max_pending_approvals = cap;
  api('/zlauder/monitor/mode', { method: 'POST', body: JSON.stringify(body) })
    .then(r => r.ok ? toast('posture set: ' + body.mode + (body.max_pending_approvals != null ? ` &middot; cap ${body.max_pending_approvals}` : ''), 'good')
                    : toast('mode change failed', 'bad'))
    .then(load);
}

/* ---------- keyboard: approve / reject loop ---------- */
document.addEventListener('keydown', e => {
  const tag = (e.target.tagName || '').toLowerCase();
  const typing = tag === 'input' || tag === 'textarea' || tag === 'select';
  if (typing) {
    if (e.key === 'Enter' && e.target.id === 'rejectReason') { e.preventDefault(); reject(selectedId); }
    if (e.key === 'Enter' && e.target.id === 'tagInput') { e.preventDefault(); tagReq(selectedId); }
    return;
  }
  const r = records.find(x => x.id === selectedId);
  if ((e.key === 'a' || e.key === 'A') && r && r.decision === 'pending') { e.preventDefault(); approve(r.id); }
  else if ((e.key === 'r' || e.key === 'R') && r && r.decision === 'pending') { e.preventDefault(); $('rejectReason')?.focus(); }
  else if (e.key === 'j' || e.key === 'k' || e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    const rows = [...document.querySelectorAll('#records [data-rec]')].map(el => el.dataset.rec);
    if (!rows.length) return;
    e.preventDefault();
    const i = rows.indexOf(selectedId);
    const fwd = e.key === 'j' || e.key === 'ArrowDown';
    const next = i < 0 ? 0 : Math.min(rows.length - 1, Math.max(0, i + (fwd ? 1 : -1)));
    selectedId = rows[next]; render();
  }
});

/* ---------- selection -> custom mask popover ---------- */
const maskPop = document.createElement('div');
maskPop.className = 'mask-pop';
maskPop.innerHTML =
  `<div class="mask-pop-row"><span class="mask-pop-pat" id="maskPat"></span></div>`
  + `<div class="mask-pop-row">`
  +   `<input id="maskEntity" placeholder="entity type (default CUSTOM_KEYWORD)" autocomplete="off">`
  + `</div>`
  + `<label class="mask-pop-cs"><input type="checkbox" id="maskCase"> case-sensitive</label>`
  + `<div class="mask-pop-actions">`
  +   `<button class="btn ghost" id="maskCancel">cancel</button>`
  +   `<button class="btn primary" id="maskGo">MASK</button>`
  + `</div>`;
document.body.appendChild(maskPop);
let pendingMask = '';
document.addEventListener('mouseup', e => {
  if (e.target.closest('.mask-pop')) return;
  // The ledger has its own ADD-keyphrase affordance; selecting text there is to copy
  // a peeked value, not to mint a mask. Don't pop the inspector's "mask selection" UI.
  if (e.target.closest('#viewLedger')) { maskPop.style.display = 'none'; return; }
  const sel = (getSelection().toString() || '').trim();
  if (sel && sel.length > 1) {
    const rng = getSelection().getRangeAt(0).getBoundingClientRect();
    pendingMask = sel;
    $('maskPat').textContent = sel.length > 40 ? sel.slice(0, 40) + '…' : sel;
    $('maskEntity').value = '';
    $('maskCase').checked = false;
    maskPop.style.display = 'block';
    maskPop.style.left = Math.min(rng.left, window.innerWidth - 280) + 'px';
    maskPop.style.top = (rng.bottom + 8) + 'px';
  } else if (!e.target.closest('.mask-pop')) {
    maskPop.style.display = 'none';
  }
});
$('maskCancel').addEventListener('click', () => { maskPop.style.display = 'none'; getSelection().removeAllRanges(); });
$('maskGo').addEventListener('click', () => {
  if (!pendingMask) return;
  const entity = ($('maskEntity').value || '').trim() || 'CUSTOM_KEYWORD';
  const caseSensitive = $('maskCase').checked;
  const sel = records.find(x => x.id === selectedId);
  const wasPending = sel && sel.decision === 'pending';
  const pat = pendingMask;
  api('/zlauder/monitor/custom-mask', {
    method: 'POST',
    body: JSON.stringify({ pattern: pat, entity_type: entity, case_sensitive: caseSensitive }),
  }).then(async r => {
    if (!r.ok) { toast('mask rejected', 'bad'); return; }
    let res = {}; try { res = await r.json(); } catch {}
    const persistNote = res.session_only
      ? ' (session-only — lost on next reload'
        + (res.persist_error ? `: ${esc(res.persist_error)}` : '') + ')'
      : (res.persisted ? ' (persisted)' : '');
    if (wasPending) {
      toast(`rule added${persistNote} &mdash; REJECT this turn to re-send masked`, 'bad');
      const ri = $('rejectReason');
      if (ri) { ri.value = `masking ${pat} — re-send`; ri.focus(); }
    } else {
      toast(`rule added${persistNote} for FUTURE traffic &mdash; THIS turn already left the machine`, 'bad');
    }
    // Keep the policy drawer's custom-mask list AND the ledger's custom-rule source
    // in sync (the ledger dedups AUTO-DETECTED against ledgerCustomRules).
    if (!$('policyDrawer').hidden) loadCustomMasks();
    refreshLedgerSources();
  });
  maskPop.style.display = 'none';
  getSelection().removeAllRanges();
});

/* ============================================================
   DATA: snapshot + SSE live stream
   ============================================================ */
let lastSnap = null;
function applySnapshot(s) {
  lastSnap = s;
  records = s.records || [];
  conversations = s.conversations || [];
  sessionTokens = s.session_tokens || [];
  if (typeof s.approval_timeout_secs === 'number') approvalTimeoutMs = s.approval_timeout_secs * 1000;
  // In OBSERVE-ONLY there is nothing to approve, so default the traffic view to
  // live activity instead of an always-empty pending queue. A hold posture keeps
  // the pending-first default. The operator's explicit pick always wins.
  if (!decisionFilterUserSet && s.mode) decisionFilter = (s.mode === 'off') ? 'live' : 'pending';
  renderHeader(s);
}
function load() {
  return api('/zlauder/monitor/snapshot')
    .then(r => r.json())
    .then(s => { applySnapshot(s); autoSelect(); render(); })
    .catch(() => toast('snapshot fetch failed', 'bad'));
}

function setLink(on) {
  $('carrier').classList.toggle('live', on);
  $('liveLabel').textContent = on ? 'LIVE' : 'LINK';
}

load().then(refreshLedgerSources);

const es = new EventSource(`/zlauder/monitor/events?key=${encodeURIComponent(key)}`);
es.onopen = () => setLink(true);
es.onerror = () => setLink(false);
es.onmessage = e => {
  let ev;
  try { ev = JSON.parse(e.data); } catch { return; }
  if (ev.event === 'snapshot') {
    applySnapshot(ev.data);
    autoSelect();
    render();
  } else if (ev.event === 'record') {
    const rec = ev.data;
    const isNew = !records.some(r => r.id === rec.id);
    const wasSelectedPending = rec.id === selectedId;
    const prev = records.find(r => r.id === rec.id);
    records = [rec, ...records.filter(r => r.id !== rec.id)];
    // Augment the durable ledger live from this record's tokens — the AUTO-DETECTED
    // list otherwise only refreshes on full snapshots (per-record SSE frames carry no
    // session_tokens). Dedup by token handle; the next snapshot reconciles to the
    // authoritative server set (counts / first_seen / class). A token masked only by
    // count_tokens still lands on the next snapshot (that path emits no SSE frame).
    for (const t of (rec.tokens || [])) {
      if (!sessionTokens.some(s => s.token === t.token)) {
        sessionTokens.push({ token: t.token, value: t.value, entity_kind: t.entity_kind, class: 'auto_pii', peekable: true, count: 1 });
      }
    }
    // Bound the client ledger like the server (oldest-first; live appends are newest).
    if (sessionTokens.length > MAX_SESSION_TOKENS) sessionTokens.splice(0, sessionTokens.length - MAX_SESSION_TOKENS);
    if (lastSnap) {
      const pending = records.filter(r => r.decision === 'pending').length;
      renderHeader({ ...lastSnap, pending_count: pending });
    }
    // Death toast: the selected hold flipped to a terminal failure state.
    if (wasSelectedPending && prev && prev.decision === 'pending'
        && ['timed_out', 'rejected', 'upstream_error'].includes(rec.decision)) {
      toast(`turn ${rec.turn_index}: ${decisionInfo(rec.decision).label.toUpperCase()} &mdash; the hold is gone`, 'bad');
      $('detail').classList.add('death-flash');
      setTimeout(() => $('detail').classList.remove('death-flash'), 900);
    }
    autoSelect();
    render(isNew ? rec.id : null);
    if (isNew && rec.decision === 'pending') toast(`HOLD &mdash; turn ${rec.turn_index} awaiting review`, 'bad');
  }
};

/* ---------- live countdown ticker ---------- */
setInterval(() => {
  let anyPending = false;
  document.querySelectorAll('[data-countdown]').forEach(el => {
    const r = records.find(x => x.id === el.dataset.countdown);
    if (!r || r.decision !== 'pending') return;
    anyPending = true;
    const rem = remainingMs(r);
    const clk = fmtClock(rem);
    el.innerHTML = `&#9201; ${clk}`;
    el.classList.remove('warn', 'crit');
    const c = clockClass(rem);
    if (c) el.classList.add(c);
  });
  // Live streaming timers for in-flight turns.
  document.querySelectorAll('[data-elapsed]').forEach(el => {
    const r = records.find(x => x.id === el.dataset.elapsed);
    if (!r || r.decision !== 'in_flight') return;
    el.innerHTML = `&#9201; ${fmtClock(elapsedMs(r))} streaming`;
  });
  // When a clock hits zero the server reject is imminent; refresh to catch it.
  if (anyPending) {
    const expired = records.some(r => r.decision === 'pending' && remainingMs(r) <= 0);
    if (expired) load();
  }
}, 1000);

/* ============================================================
   POLICY DRAWER  —  the human masking-policy surface.
   Reads GET /zlauder/config (the live snapshot) and drives:
     - profile      via POST /zlauder/profile/{name}?scope=…
     - threshold    via merge PUT /zlauder/config {score_threshold}
     - categories   via merge PUT /zlauder/config {enabled_categories}
     - ML toggle    via POST /zlauder/ml/{enable,disable}
     - custom masks via GET/DELETE /zlauder/monitor/custom-mask
   Reuses the authed api() wrapper. This panel owns POLICY (what is
   masked); the header POSTURE owns the review HOLD (separate surface).
   ============================================================ */
const CATEGORIES = ['secrets', 'financial', 'identity', 'contact', 'personal'];

/* The per-profile threshold/categories/operator seeds — a verbatim mirror of the
   engine's EngineConfig::for_profile (config.rs Profile::default_*). Used ONLY to
   detect when the live config has diverged from the selected profile, so the
   dropdown can be marked (modified) instead of silently misrepresenting the policy
   (and so re-APPLYing won't silently clobber a hand-tuned threshold/categories). */
const PROFILE_SEEDS = {
  strict:       { threshold: 0.4, categories: ['secrets', 'financial', 'identity', 'contact', 'personal'], operator: 'token' },
  balanced:     { threshold: 0.5, categories: ['secrets', 'financial', 'identity', 'contact'],             operator: 'token' },
  minimal:      { threshold: 0.6, categories: ['secrets', 'financial'],                                    operator: 'token' },
  secrets_only: { threshold: 0.6, categories: ['secrets'],                                                 operator: 'token' },
};

function sameSet(a, b) {
  const sa = new Set(a), sb = new Set(b);
  if (sa.size !== sb.size) return false;
  for (const v of sa) if (!sb.has(v)) return false;
  return true;
}

/* Has the live config diverged from `profile`'s for_profile() seed? */
function profileDiverged(profile, cfg) {
  const seed = PROFILE_SEEDS[profile];
  if (!seed) return false;
  const thr = typeof cfg.score_threshold === 'number' ? cfg.score_threshold : seed.threshold;
  if (Math.abs(thr - seed.threshold) > 1e-6) return true;
  if (!sameSet(cfg.enabled_categories || [], seed.categories)) return true;
  const op = (cfg.default_operator && cfg.default_operator.kind) || 'token';
  if (op !== seed.operator) return true;
  return false;
}

function openPolicy()  { $('policyScrim').hidden = false; $('policyDrawer').hidden = false; loadPolicy(); }
function closePolicy() { $('policyScrim').hidden = true;  $('policyDrawer').hidden = true; }

$('policyOpen').addEventListener('click', openPolicy);
$('policyClose').addEventListener('click', closePolicy);
$('policyScrim').addEventListener('click', closePolicy);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !$('policyDrawer').hidden) closePolicy();
});

/* ---- render the live config into the controls ---- */
function applyPolicyConfig(snap) {
  const cfg = (snap && snap.config) || {};
  const ml = (snap && snap.ml) || {};

  // profile
  if (cfg.profile) $('polProfile').value = cfg.profile;

  // operator (read-only display; profiles differ on this axis — e.g. Strict now
  // tokenizes (reversible) rather than redacting, so the user must be able to SEE it)
  const op = (cfg.default_operator && cfg.default_operator.kind) || '—';
  $('polOperator').textContent = op === 'token' ? 'token (reversible)'
                              : op === 'redact' ? 'redact (irreversible)'
                              : op;

  // threshold
  if (typeof cfg.score_threshold === 'number') {
    $('polThresh').value = cfg.score_threshold;
    $('polThreshVal').textContent = cfg.score_threshold.toFixed(2);
  }

  // categories
  const on = new Set(cfg.enabled_categories || []);
  $('polCats').querySelectorAll('input[type=checkbox]').forEach(cb => { cb.checked = on.has(cb.value); });

  // Has the live config drifted from the selected profile? If so the dropdown alone
  // is misleading — mark it (modified) and warn that re-APPLY overwrites hand edits.
  const sel = $('polProfile').value;
  const hint = $('polProfileHint');
  if (profileDiverged(sel, cfg)) {
    $('polProfile').classList.add('pol-modified');
    hint.textContent = `live config differs from "${sel}" — APPLY will overwrite your threshold/category edits.`;
    hint.classList.add('pol-warn');
  } else {
    $('polProfile').classList.remove('pol-modified');
    hint.textContent = 'A profile sets threshold + categories + operator together.';
    hint.classList.remove('pol-warn');
  }

  // ML
  const status = ml.status || (ml.enabled ? 'loading' : 'disabled');
  mlStatus = status;
  $('polMlToggle').checked = !!ml.enabled;
  $('polMlLabel').textContent = ml.enabled ? 'enabled' : 'disabled';
  const sEl = $('polMlStatus');
  sEl.textContent = status;
  sEl.className = 'pol-ml-status ' + status;
  $('polMlModel').textContent = ml.model ? `model: ${ml.model}${ml.error ? ' — ' + ml.error : ''}` : '';

  refreshPersonalTier();
}

/* Personal (PERSON/LOCATION/ORGANIZATION) is ML-only — no regex can find arbitrary
   names — so it masks NOTHING unless the openai/privacy-filter model is loaded AND
   ready. We do NOT disable the checkbox (you may want to pre-arm Personal before
   turning the model on), but we flag it hard so it's never mistaken for active:
   a persistent "needs ML" tag, plus an active warning + amber "inert" row whenever
   Personal is enabled while the model is not `ready`. The warning is keyed on the
   live ml STATUS, so it auto-clears the moment the model goes ready. */
let mlStatus = 'disabled';
function refreshPersonalTier() {
  const box = $('polCats').querySelector('input[value=personal]');
  const on = !!(box && box.checked);
  const ready = mlStatus === 'ready';
  const warn = $('polPersonalWarn');
  $('polCheckPersonal').classList.toggle('inert', on && !ready);
  if (!on || ready) { warn.hidden = true; warn.textContent = ''; return; }
  const msg = mlStatus === 'loading'
    ? 'Personal entities are not masked <b>yet</b> — the openai/privacy-filter model is still <b>loading</b>. Names, locations &amp; organisations start masking the moment it is ready.'
    : mlStatus === 'failed'
    ? '&#9888; Personal is enabled but the model <b>FAILED to load</b> — names, locations &amp; organisations are <b>NOT being masked</b>. Re-enable the model under ML RECOGNIZER below, or untick Personal.'
    : '&#9888; Personal only masks with the ML model, which is <b>OFF</b>. Names, locations &amp; organisations are <b>NOT being masked</b> right now. Enable &amp; load the model under ML RECOGNIZER below.';
  warn.innerHTML = msg;
  warn.hidden = false;
}

function loadPolicy() {
  api('/zlauder/config')
    .then(r => r.ok ? r.json() : Promise.reject(new Error('config fetch failed')))
    .then(applyPolicyConfig)
    .catch(() => toast('policy fetch failed', 'bad'));
  loadCustomMasks();
}

/* Re-evaluate the divergence indicator against the CURRENTLY-displayed controls
   (profile dropdown + threshold + checked categories), without a server round-trip.
   Lets the (modified) badge react as the user changes the dropdown or edits controls
   before pressing SET/APPLY. */
function refreshDivergence() {
  const cfg = {
    score_threshold: Number($('polThresh').value),
    enabled_categories: [...$('polCats').querySelectorAll('input:checked')].map(cb => cb.value),
    default_operator: { kind: ($('polOperator').textContent.split(' ')[0]) || 'token' },
  };
  const sel = $('polProfile').value;
  const hint = $('polProfileHint');
  if (profileDiverged(sel, cfg)) {
    $('polProfile').classList.add('pol-modified');
    hint.textContent = `live config differs from "${sel}" — APPLY will overwrite your threshold/category edits.`;
    hint.classList.add('pol-warn');
  } else {
    $('polProfile').classList.remove('pol-modified');
    hint.textContent = 'A profile sets threshold + categories + operator together.';
    hint.classList.remove('pol-warn');
  }
}
$('polProfile').addEventListener('change', refreshDivergence);
$('polCats').addEventListener('change', () => { refreshDivergence(); refreshPersonalTier(); });

/* ---- profile ---- */
$('polApplyProfile').addEventListener('click', () => {
  const name = $('polProfile').value;
  const scope = $('polScope').value;
  api(`/zlauder/profile/${encodeURIComponent(name)}?scope=${encodeURIComponent(scope)}`, { method: 'POST' })
    .then(r => r.ok ? r.json() : Promise.reject(new Error('profile rejected')))
    .then(snap => {
      applyPolicyConfig(snap);
      const where = snap.session_only ? 'session-only (not persisted)'
                  : (snap.persisted ? `persisted → ${snap.persisted}` : 'applied');
      if (snap.persist_error) toast(`profile ${esc(name)} applied LIVE but persist failed: ${esc(snap.persist_error)}`, 'bad');
      else toast(`profile <b>${esc(name)}</b> — ${esc(where)}`, 'good');
    })
    .catch(() => toast('profile change failed', 'bad'));
});

/* ---- threshold ---- */
$('polThresh').addEventListener('input', e => { $('polThreshVal').textContent = Number(e.target.value).toFixed(2); refreshDivergence(); });
$('polApplyThresh').addEventListener('click', () => {
  const v = Number($('polThresh').value);
  putConfigMerge({ score_threshold: v }, `threshold ${v.toFixed(2)}`);
});

/* ---- categories ---- */
$('polApplyCats').addEventListener('click', () => {
  const sel = [...$('polCats').querySelectorAll('input:checked')].map(cb => cb.value);
  putConfigMerge({ enabled_categories: sel }, `categories: ${sel.join(', ') || 'none'}`);
});

/* shared merge-PUT helper */
function putConfigMerge(body, label) {
  api('/zlauder/config', { method: 'PUT', body: JSON.stringify(body) })
    .then(r => r.ok ? r.json() : r.text().then(t => Promise.reject(new Error(t))))
    .then(snap => { applyPolicyConfig(snap); toast(`set ${esc(label)}`, 'good'); })
    .catch(err => toast(`set failed: ${esc(err.message || 'rejected')}`, 'bad'));
}

/* ---- ML toggle ---- */
$('polMlToggle').addEventListener('change', e => {
  const on = e.target.checked;
  api(`/zlauder/ml/${on ? 'enable' : 'disable'}`, { method: 'POST' })
    .then(r => r.ok ? r.json() : Promise.reject(new Error('ml toggle failed')))
    .then(snap => {
      applyPolicyConfig(snap);
      toast(on ? 'ML enabling — loading model in background' : 'ML disabled', on ? 'good' : 'bad');
    })
    .catch(() => { e.target.checked = !on; toast('ML toggle failed', 'bad'); });
});

/* ---- custom masks: list + remove ---- */
function loadCustomMasks() {
  api('/zlauder/monitor/custom-mask')
    .then(r => r.ok ? r.json() : Promise.reject(new Error('mask list failed')))
    .then(renderCustomMasks)
    .catch(() => { $('polMasks').innerHTML = `<div class="pol-masks-empty">could not load custom masks</div>`; });
}

function renderCustomMasks(data) {
  const rules = (data && data.custom_replacements) || [];
  $('polMaskCount').textContent = rules.length;
  if (!rules.length) {
    $('polMasks').innerHTML = `<div class="pol-masks-empty">No custom masks. Select text in a request to add one.</div>`;
    return;
  }
  $('polMasks').innerHTML = rules.map(c =>
    `<div class="pol-mask">`
    + `<span class="pol-mask-pat">${c.is_regex ? '/' : ''}${esc(c.pattern)}${c.is_regex ? '/' : ''}</span>`
    + `<span class="pol-mask-kind">${esc(c.entity_type)}</span>`
    + `<span class="pol-mask-cs">${c.case_sensitive ? 'CS' : 'ci'}</span>`
    + `<button class="pol-mask-x" data-mask-pat="${attr(c.pattern)}" data-mask-kind="${attr(c.entity_type)}" aria-label="remove mask ${attr(c.pattern)}">remove</button>`
    + `</div>`
  ).join('');
}

$('polMasks').addEventListener('click', e => {
  const btn = e.target.closest('.pol-mask-x');
  if (!btn) return;
  const pattern = btn.dataset.maskPat;
  const entity_type = btn.dataset.maskKind;
  api('/zlauder/monitor/custom-mask', { method: 'DELETE', body: JSON.stringify({ pattern, entity_type }) })
    .then(r => r.ok ? r.json() : Promise.reject(new Error('remove failed')))
    .then(res => {
      toast(`removed mask <b>${esc(pattern)}</b>${res.removed_persisted ? ' (live + persisted)' : ' (live only)'}`, 'good');
      loadCustomMasks();
      refreshLedgerSources();
    })
    .catch(() => toast('mask remove failed', 'bad'));
});
