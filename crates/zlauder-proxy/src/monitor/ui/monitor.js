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
     ResponseProgress{ id, status, response_preview, response_surfaces[] }  // SSE 'response_progress'
   Surfaces are rendered run-by-run with ZERO client offset arithmetic.
   The sidebar conversation list is recomputed CLIENT-side from records (server labels
   seed convoLabels) so a brand-new thread appears live on its first 'record' frame
   instead of only on the next full snapshot.
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
let convoLabels = {};             // id -> label (server-authoritative from snapshots; derived for new threads)
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
let peekAll = false;                  // PEEK ALL master: force every peekable row open (local only, default off)
let denoise = localStorage.getItem('zlDenoise') === '1';  // DE-NOISE: group ledger by lane + fold scaffolding (default OFF — the complete view is the baseline)
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

/* ---------- entity SEVERITY tiers (presentation re-rank — NEVER detection) ----------
   Signal-to-noise in the live data is inverted: the loudest chips are the false positives
   (tool-name PERSON, session-UUID US_BANK_NUMBER, infra URL/IP). Sort + saturate genuine,
   high-confidence exposures FIRST; demote the low-precision ML/loose-regex kinds to a muted
   tier. Every kind is still masked, counted, and in the ledger — only the VISUAL order and
   weight change. UNCERTAIN: ideally these tiers come from the engine's Category list so they
   can't drift; mirrored here for now (see isSecretClass for the same drift caveat). */
const SEV_CRITICAL = /API_KEY|AWS_|AZURE_KEY|GCP_|PRIVATE_KEY|JWT|CREDIT_CARD|IBAN|CRYPTO|ROUTING|SSN|ITIN|NATIONAL_ID|PASSPORT|DRIVER_LICEN|DRIVING_LICEN|MEDICAL_LICENSE|NPI|MBI|NHS|NINO|EMAIL|PHONE/;
const SEV_LOW = /PERSON|LOCATION|ORGANIZATION|US_BANK_NUMBER|URL|IP_ADDRESS|MAC_ADDRESS|DATE_TIME|DOMAIN/;
function entityTier(kind) {
  const k = String(kind || '').toUpperCase();
  if (SEV_CRITICAL.test(k)) return 0;   // genuine high-confidence PII/secret — saturated, first
  if (SEV_LOW.test(k)) return 2;        // low-precision / false-positive-heavy — muted, last
  return 1;                              // everything else — default amber
}
function sevClass(kind) { const t = entityTier(kind); return t === 0 ? 'sev-crit' : t === 2 ? 'sev-low' : ''; }
/* rollup() re-ordered by sensitivity tier first, then count desc. */
function rollupTiered(tokens) {
  return rollup(tokens).sort((a, b) => {
    const ta = entityTier(a[0]), tb = entityTier(b[0]);
    return ta !== tb ? ta - tb : b[1] - a[1];
  });
}
function rollupChips(tokens, cls) {
  const r = rollupTiered(tokens);
  if (!r.length) return '';
  return r.map(([k, n]) =>
    `<span class="kind-chip ${sevClass(k)} ${cls || ''}">${n}× ${esc(k)}</span>`).join('');
}

/* ---------- risk: non-empty surfaces but nothing masked ---------- */
function isNothingMaskedRisk(r) {
  const surfaces = r.request_surfaces || [];
  if (!surfaces.length) return false;
  const tokenRuns = surfaces.some(s => (s.runs || []).some(run => run.token));
  return !tokenRuns;
}

/* B2: a tool surface (tool_result / tool_use) that carries text but ZERO masked
   tokens is data pulled off this machine with nothing redacted — exactly where an
   undetected secret (internal hostname, ticket id, key the classifier missed) leaks.
   isNothingMaskedRisk() is all-or-nothing per record, so it stays silent whenever ANY
   other surface is masked; this catches it per-surface. Scoped to tool_* kinds, which
   are never harness boilerplate, so it never lights up the base prompt. */
function isUnmaskedToolSurface(s) {
  if (!s || (s.kind !== 'tool_result' && s.kind !== 'tool_use')) return false;
  const runs = s.runs || [];
  const hasText = runs.some(run => run.text && run.text.trim());
  const hasToken = runs.some(run => run.token);
  return hasText && !hasToken;
}
function unmaskedToolSurfaces(r) {
  return (r.request_surfaces || []).filter(isUnmaskedToolSurface);
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

/* `direction` defaults to 'outbound' (a request surface, masked text headed to the
   provider). 'inbound' marks a RESPONSE surface: text the provider sent us, with its
   tokens already re-hydrated LOCALLY for review — it is NOT egressing, so it never wears
   the red NEW/egress framing. The direction is a property of WHICH panel renders the
   surface (response vs request), not of provenance: the same assistant text is inbound in
   the RESPONSE panel and outbound (re-masked) when the harness re-sends it as request
   transcript next turn. */
function renderSurface(s, addedSet, direction) {
  const inbound = direction === 'inbound';
  // Egress framing (NEW / amber) is for outbound surfaces only; a received reply is never
  // "new plaintext leaving the machine".
  const isNew = !inbound && addedSet && addedSet.has(s.block_hash);
  const hasTokenRun = (s.runs || []).some(run => run.token);
  const kindClass = 'kind-' + s.kind;
  const role = s.role ? ` &middot; ${esc(s.role)}` : '';
  const dirTag = inbound
    ? `<span class="dir-tag dir-in" title="received from the provider and re-hydrated locally for your review — this content is NOT egressing">RECEIVED &larr; MODEL</span>`
    : '';
  // The "re-hydrated locally" note only makes sense when something was actually un-masked
  // here; plain prose with no token runs gets no note.
  const rehydNote = (inbound && hasTokenRun)
    ? `<div class="surface-note">values below are re-hydrated locally — the provider sent tokens; nothing here egresses</div>`
    : '';
  return `<div class="surface ${inbound ? 'surface-in' : ''} ${isNew ? 'is-new' : ''}">`
    + `<div class="surface-head">`
    +   `<span class="kind-tag ${kindClass}">${esc(s.kind)}</span>`
    +   dirTag
    +   `<span class="surface-label">${esc(s.label)}${role}</span>`
    +   (isNew ? `<span class="new-flag">NEW</span>` : '')
    +   (isUnmaskedToolSurface(s) ? `<span class="new-flag warn-flag" title="tool output with nothing masked — eyeball for unredacted data">UNMASKED</span>` : '')
    +   `<span class="surface-hash" title="block hash ${esc(s.block_hash)}">${esc(s.block_hash)}</span>`
    + `</div>`
    + rehydNote
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

/* Distinct NEW plaintext values about to leave this turn — the number the operator
   actually cares about (vs. raw "+N surfaces", which is mostly resent plumbing).
   Reuses newPlaintext()'s new-surface scoping, so it works on every record, incl.
   observe mode where the held-request plaintext block never renders. */
function newPiiCount(r) { return newPlaintext(r).length; }

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
    // B2: "no NEW surface" is not "no risk" — a resent tool surface that ships data
    // with nothing masked is silenced by the all-or-nothing isNothingMaskedRisk when
    // any other surface is masked. Surface it here instead of a falsely-calm card.
    const unmaskedTools = unmaskedToolSurfaces(r);
    if (unmaskedTools.length) {
      return `<div class="spotlight warn">`
        + `<div class="spotlight-head">`
        +   `<span class="spotlight-icon">&#9888;</span>`
        +   `<span class="spotlight-title">UNMASKED TOOL OUTPUT</span>`
        +   `<span class="spotlight-sub">${unmaskedTools.length} resent tool surface(s) ship data with nothing masked &mdash; eyeball for unredacted secrets</span>`
        + `</div>`
        + `<div class="spotlight-body">`
        +   unmaskedTools.map(s => renderSurface(s, null)).join('')
        + `</div></div>`;
    }
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

  const piiCount = newPiiCount(r);
  return `<div class="spotlight">`
    + `<div class="spotlight-head">`
    +   `<span class="spotlight-icon">&#9650;</span>`
    +   `<span class="spotlight-title">DELTA &middot; ${newSurfaces.length} NEW SURFACE${newSurfaces.length === 1 ? '' : 'S'}`
    +     (piiCount ? ` &middot; <span class="spotlight-pii">${piiCount} NEW PII</span>` : '') + `</span>`
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

  const turnLabel = r.human_turn_index > 0 ? r.human_turn_index : r.turn_index;
  const egressNote = (r.human_turn_index > 0 && r.turn_index !== r.human_turn_index)
    ? ` &middot; egress T${r.turn_index}` : '';
  const head = `<div class="review-head">`
    + `<div><div class="rh-id">TURN ${turnLabel}`
    +   `<small title="${esc(r.id)}">${esc(r.method)} ${esc(r.endpoint)} &middot; ${esc(r.id)}${egressNote}</small></div>${rollHead}</div>`
    + `<div class="rh-spacer"></div>`
    + `<div class="rh-controls">`
    +   `<label class="reveal-toggle" title="show masked values inline in this browser — local only, never sent"><input type="checkbox" id="revealToggle" ${revealValues ? 'checked' : ''}> peek values</label>`
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
  const streaming = r.decision === 'in_flight';
  // `hasResp` (any response field at all) decides whether the panel EXISTS;
  // `respHasContent` (real surfaces or NON-EMPTY preview) decides content-vs-empty. The
  // first streaming progress frame can carry response_preview === "" before any text
  // accumulates — that must show the waiting state, not an empty bordered <pre>.
  const hasResp = r.response_preview != null || respSurfaces.length;
  const respHasContent = respSurfaces.length || (r.response_preview != null && r.response_preview !== '');
  // Auto-open while the reply streams so the operator watches it land; the live badge
  // makes the in-progress state unmistakable. Count shows HTTP status once finalized.
  const respCount = streaming
    ? `<span class="stream-live">&#9679; streaming</span>`
    : (r.response_status ? 'HTTP ' + r.response_status : '');
  // The RESPONSE panel is INBOUND — provider → here → you. Its surfaces show values
  // re-hydrated locally; they are not egressing, so the panel reads in the calm inbound
  // (cyan) register, never the red egress register. A streaming tail sentinel lets the
  // SSE handler keep the growing reply in view (sticky-follow) without yanking the
  // operator if they scrolled up to read the request.
  const fullResponse = (hasResp || streaming) ? `<details class="panel panel-response"${streaming ? ' open' : ''}>`
    + `<summary><span class="panel-title">RESPONSE</span>`
    +   `<span class="dir-tag dir-in" title="received from the provider and re-hydrated locally — not egressing">&larr; FROM MODEL</span>`
    +   `<span class="panel-count">${respCount}</span></summary>`
    + `<div class="panel-body">`
    +   (respHasContent
          ? (respHasTokenRun
              ? respSurfaces.map(s => renderSurface(s, null, 'inbound')).join('')
              : `<pre class="payload payload-in">${renderSpanned(r.response_preview, r.response_spans)}</pre>`)
          : `<div class="empty-note">${streaming ? 'Waiting for the model&rsquo;s reply&hellip;' : 'No reviewable response content.'}</div>`)
    +   (streaming ? `<div id="streamTail" aria-hidden="true"></div>` : '')
    + `</div></details>`
    : '';

  const tagComposer = `<details class="panel">`
    + `<summary><span class="panel-title">ANNOTATE</span></summary>`
    + `<div class="panel-body"><div class="tag-composer">`
    +   `<input id="tagInput" placeholder="add tag to this intercept&hellip;" autocomplete="off">`
    +   `<button class="btn ghost" data-act="tag" data-id="${esc(r.id)}">TAG</button>`
    + `</div></div></details>`;

  // Detail ordering is DELTA-first then RESPONSE-first: the two things that actually change
  // turn-to-turn (what's newly egressing = the spotlight, and what came back = the response)
  // lead, and the static bookkeeping (full token ledger + full re-sent request) follows. For
  // a held/pending request there is no response yet (fullResponse === '') so this collapses
  // to the egress-review order; once a reply streams/finalizes it rises above the request dump.
  d.innerHTML = head + verdict + plaintextBlock + spotlight + fullResponse + tokenLedger + fullRequest + tagComposer;
}

/* ============================================================
   CONVERSATIONS derived client-side from records
   The server computes the same list (store.rs conversations_from_records), but only
   ships it on full snapshots. Mirroring it here means a new thread (and growing turn
   counts) shows the instant its 'record' frame lands — no refresh, no filter-clearing.
   Server labels seed convoLabels; an unseen thread derives one from its surfaces the
   same way the server does (first genuine user message, skipping harness scaffolding).
   ============================================================ */
function deriveLabel(rec) {
  const surfaces = rec.request_surfaces || [];
  const notHarness = s => s.provenance !== 'harness_frame' && s.provenance !== 'harness_meta';
  const pick = surfaces.find(s => s.provenance === 'user_input')
    || surfaces.find(s => s.kind === 'message' && s.role === 'user' && notHarness(s))
    || surfaces.find(s => s.kind === 'message' && notHarness(s));
  if (!pick) return null;
  const text = (pick.runs || []).map(r => r.text).join('').split(/\s+/).filter(Boolean).join(' ');
  if (!text) return null;
  const chars = [...text];
  return chars.length > 48 ? chars.slice(0, 48).join('') + '…' : text;
}
/* Mirror of server store.rs::conversation_label — the fallback when no message snippet is
   derivable, so the live sidebar matches the next snapshot's label instead of flashing the
   raw id. (endpoint leaf + last-6 id tail, e.g. "messages · a1b2c3".) */
function conversationLabel(endpoint, id) {
  const parts = String(endpoint || '').split(/[/:]/).filter(Boolean);
  const leaf = parts.length ? parts[parts.length - 1] : String(endpoint || '');
  id = String(id || '').trim();
  if (id === 'unknown' || id === '') return `${leaf} · unknown`;
  const chars = [...id];
  const tail = chars.length > 6 ? chars.slice(-6).join('') : id;
  return tail === id ? id : `${leaf} · ${tail}`;
}
function conversationsFromRecords() {
  const metas = new Map();
  for (const r of records) {
    let m = metas.get(r.conversation_id);
    if (!m) {
      // Cache ONLY a real derived snippet — never the fallback — so a later turn whose
      // transcript surfaces the genuine prompt upgrades a thread that opened unlabeled.
      let label = convoLabels[r.conversation_id];
      if (label == null) {
        const derived = deriveLabel(r);
        if (derived) { label = derived; convoLabels[r.conversation_id] = derived; }
        else label = conversationLabel(r.endpoint, r.conversation_id);
      }
      m = { id: r.conversation_id, label, turn_count: 0, last_updated_ms: 0, pending_count: 0 };
      metas.set(r.conversation_id, m);
    }
    // Human turns (one prompt + its tool cycle = one turn); fall back to per-request index.
    const ht = r.human_turn_index > 0 ? r.human_turn_index : r.turn_index;
    m.turn_count = Math.max(m.turn_count, ht);
    m.last_updated_ms = Math.max(m.last_updated_ms, Number(r.updated_ms));
    if (r.decision === 'pending') m.pending_count++;
  }
  return [...metas.values()].sort((a, b) => b.last_updated_ms - a.last_updated_ms);
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

  // Bracket tool-cycle requests under their human turn (chunk 3): the head of a human turn
  // is its lowest-turn_index request; later requests sharing the same (conversation,
  // human_turn) are tool-cycle continuations, shown indented under it. Computed over ALL
  // records so a filtered-out head still demotes its children. No reordering — the triage
  // sort (pending-first) is untouched; this only relabels + indents.
  const headTurn = {};
  for (const r of records) {
    if (!r.human_turn_index) continue;
    const k = r.conversation_id + ' ' + r.human_turn_index;
    if (!(k in headTurn) || r.turn_index < headTurn[k]) headTurn[k] = r.turn_index;
  }
  const isToolCycle = r => r.human_turn_index > 0
    && headTurn[r.conversation_id + ' ' + r.human_turn_index] !== r.turn_index;

  $('records').innerHTML = visible.length ? visible.map(r => {
    const tc = (r.tokens || []).length;
    const di = decisionInfo(r.decision);
    const risk = isNothingMaskedRisk(r);
    const newCount = (r.delta && !r.delta.is_first) ? (r.delta.added_surface_hashes || []).length : -1;
    const piiCount = newPiiCount(r);
    const pending = r.decision === 'pending';
    const inflight = r.decision === 'in_flight';
    const rem = remainingMs(r);
    const ela = elapsedMs(r);
    const roll = rollupTiered(r.tokens).slice(0, 3)
      .map(([k, n]) => `<span class="rec-kind ${sevClass(k)}">${n}×${esc(k)}</span>`).join('');
    const ht = r.human_turn_index;
    const child = isToolCycle(r);
    const turnPip = ht > 0
      ? (child
          ? `<span class="rec-turn child" title="tool-cycle egress within human turn ${ht} &middot; request ${r.turn_index}">&#8627; T${ht}</span><span class="rec-cycle">req ${r.turn_index}</span>`
          : `<span class="rec-turn" title="human turn ${ht} &middot; request ${r.turn_index}">T${ht}</span>`)
      : `<span class="rec-turn">T${r.turn_index}</span>`;
    return `<div class="rec ${pending ? 'pending' : ''} ${inflight ? 'inflight' : ''} ${risk ? 'risk' : ''} ${child ? 'tool-cycle' : ''} ${selectedId === r.id ? 'active' : ''} ${flashId === r.id ? 'flash' : ''}" data-rec="${esc(r.id)}">`
      + `<div class="rec-top">`
      +   turnPip
      +   `<span class="rec-endpoint">${esc(r.endpoint)}</span>`
      +   (pending ? `<span class="rec-clock ${clockClass(rem)}" data-countdown="${esc(r.id)}">&#9201; ${fmtClock(rem)}</span>` : '')
      +   (inflight ? `<span class="rec-clock live" data-elapsed="${esc(r.id)}">&#9201; ${fmtClock(ela)} streaming</span>` : '')
      +   (r.delta && r.delta.is_first ? `<span class="new-flag">FIRST</span>`
            : (r.delta && r.delta.prev_unavailable ? `<span class="new-flag warn-flag">?</span>`
            : (newCount > 0 ? `<span class="new-flag">+${newCount}</span>` : '')))
      +   (piiCount > 0 ? `<span class="new-flag pii-flag" title="${piiCount} new plaintext value(s) about to leave this machine this turn">${piiCount} PII</span>` : '')
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

/* ---------- protection status: the plain-language "am I protected?" line ----------
   Reads only state the UI already holds (snapshot mode/pending + the durable ledger size +
   the live policy categories). Aggregate-only by design — no per-entity breakdown leaks
   here (the ledger below is where details live). */
function renderProtectionStatus() {
  const el = $('protectionStatus');
  if (!el) return;
  if (!lastSnap) { el.hidden = true; return; }
  el.hidden = false;
  // Masking is genuinely active only if the engine master switch is ON and at least one
  // detector can ACTUALLY produce masks. The complete set of masking sources (each
  // independent of the others): any regex category (secrets/financial/identity/contact)
  // masks immediately; `personal` masks ONLY once the ML model is `ready`; any custom
  // keyphrase rule masks; and any per-entity operator that is not `keep` masks even with no
  // category selected. Counting only categories would BOTH overstate (personal-only, ML off)
  // AND understate (custom/operator-only) — the line claims a security property, so it must
  // reflect every path.
  const cfg = (committedPolicy && committedPolicy.config) || null;
  const cats = (cfg && cfg.enabled_categories) || null;
  const masterOff = !!(committedPolicy && committedPolicy.enabled === false); // top-level engine switch
  const regexCat = !!(cats && cats.some(c => c !== 'personal'));
  const personalActive = !!(cats && cats.includes('personal') && mlStatus === 'ready');
  const customActive = !!(cfg && Array.isArray(cfg.custom_replacements) && cfg.custom_replacements.length);
  // A detected entity is only MASKED if its RESOLVED operator is not `keep` (`keep` = detected
  // but left verbatim). Categories/personal use the default operator unless a per-entity
  // override applies, so an enabled category masks only when the default operator masks
  // (`defaultMasks`) OR some per-entity operator masks (`opMasks`). A `keep` default
  // (observe-without-masking) means those categories mask nothing.
  // RESIDUAL (documented, not handled): default masks but EVERY entity is individually
  // keep-overridden — would need the engine's category→entity map to detect; no realistic
  // config does this, and the precise check belongs server-side if ever needed.
  const defaultMasks = !(cfg && cfg.default_operator && cfg.default_operator.kind === 'keep');
  const opMasks = !!(cfg && cfg.entity_operators
      && Object.values(cfg.entity_operators).some(op => op && op.kind && op.kind !== 'keep'));
  const catMasks = (regexCat || personalActive) && defaultMasks;
  // Before the policy loads (committedPolicy null) assume ON — we ARE a masking proxy; it
  // self-corrects on the first config load.
  const maskingOn = committedPolicy
      ? (!masterOff && (catMasks || customActive || opMasks))
      : true;
  const personalOnly = !!(cats && cats.length === 1 && cats[0] === 'personal');
  const offReason = masterOff ? ' &mdash; engine disabled'
      : personalOnly ? ' &mdash; only Personal is on and the ML model is not ready'
      : !defaultMasks ? ' &mdash; detectors set to keep (observing, not masking)'
      : ' &mdash; no active detectors';
  const masked = sessionTokens.length;
  const pend = lastSnap.pending_count || 0;
  const modeText = lastSnap.mode === 'off'
      ? 'OBSERVE — nothing held for approval'
      : lastSnap.mode === 'manual_all_llm'
      ? `HOLD ALL LLM — ${pend} held for approval`
      : `HOLD ON DETECTION — ${pend} held for approval`;
  const mlNote = (mlStatus && mlStatus !== 'disabled' && mlStatus !== 'ready')
      ? ` &middot; names/locations masking <b>${esc(mlStatus)}</b>` : '';
  el.className = 'protection-status ' + (maskingOn ? 'ok' : 'off');
  const lead = maskingOn
      ? `<span class="ps-dot good">&#9679;</span><b>Masking ON</b>`
      : `<span class="ps-dot bad">&#9888;</span><b>Masking OFF</b>${offReason}`;
  el.innerHTML = lead
    + ` &middot; <b>${masked}</b> value${masked === 1 ? '' : 's'} masked before leaving this machine`
    + ` &middot; ${esc(modeText)}${mlNote}`;
}

function render(flashId) {
  renderChannels();
  renderTraffic(flashId);
  renderReview();
  renderLedger();
  renderViewState();
  renderProtectionStatus();
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

   Two distinct, deliberately-separated terms (do not conflate):
     - PEEK   : show plaintext in THIS browser only. Pure client state (`peeked`,
                or the `peekAll` master switch). Never sent anywhere.
     - REVEAL (to model) : allow-list the value so it egresses UNMASKED upstream to
                the LLM/context; durable, privacy-reducing → confirm first. Server-side.
   "reveal" is reserved strictly for sending plaintext to the model; local UI display
   is always "peek". Auto-detected rows whose class is non-peekable (reserved for the
   secrets engine) render locked — the value is never in the snapshot, so never peekable.
   ============================================================ */

/* A value chip: masked by default; click peeks the plaintext locally (or the PEEK ALL
   master forces it open). A non-peekable (secret-class) row renders a static lock —
   no value, no peek. */
function peekChip(rowKey, value, peekable) {
  if (peekable === false) {
    return `<span class="lv-val locked" title="secret — value withheld from the UI">••••••</span>`;
  }
  const on = peekAll || peeked.has(rowKey);
  return `<span class="lv-val peek ${on ? 'on' : ''}" data-peek="${attr(rowKey)}" tabindex="0" role="button"`
    + ` aria-label="${on ? 'hide value' : 'peek value'}"`
    + ` title="${peekAll ? 'PEEK ALL is on — values shown locally' : (on ? 'click to hide' : 'peek — show locally, not sent anywhere')}">`
    + `${on ? esc(value) : '••••••'}</span>`;
}

/* ---------- ledger provenance lanes (chunk 1) ----------
   Each durable ledger entry carries a server-derived `provenance` lane (a HINT, never a
   detection gate). The ledger GROUPS by lane so real-exposure lanes (your files, tool I/O,
   your messages) read first, and the fixed Claude Code scaffolding folds into one
   still-scanned, one-click-restorable group when DE-NOISE is on. `fold:true` lanes are the
   only ones ever collapsed; everything else (incl. unclassified) is always shown. */
const LANE_META = {
  userctx:       { tag: 'ctx',  label: 'your files (CLAUDE.md / MEMORY.md)', rank: 5, fold: false },
  tool_io:       { tag: 'tool', label: 'tool input / output',               rank: 4, fold: false },
  user_input:    { tag: 'you',  label: 'your messages',                     rank: 3, fold: false },
  assistant:     { tag: 'llm',  label: 'model output',                      rank: 2, fold: false },
  harness_frame: { tag: 'sys',  label: 'Claude Code system scaffolding',    rank: 1, fold: true  },
  harness_meta:  { tag: 'meta', label: 'transport / billing metadata',      rank: 0, fold: true  },
};
function laneMeta(lane) {
  return LANE_META[lane] || { tag: '?', label: 'unclassified — shown', rank: 3, fold: false };
}
function laneChip(lane) {
  const m = laneMeta(lane);
  return `<span class="lane-chip lane-${esc(lane || 'none')}" title="${attr(m.label)}">${esc(m.tag)}</span>`;
}

function renderLedger() {
  // ---- holds strip (keeps approve/reject reachable from the ledger) ----
  const holds = records.filter(r => r.decision === 'pending')
    .slice().sort((a, b) => Number(a.started_ms) - Number(b.started_ms));
  $('ledgerHoldsWrap').hidden = holds.length === 0;
  $('ledgerHolds').innerHTML = holds.map(r => {
    const rem = remainingMs(r);
    return `<div class="lhold" data-hold-select="${esc(r.id)}" title="open in inspector">`
      + `<span class="lhold-turn">T${r.human_turn_index > 0 ? r.human_turn_index : r.turn_index}</span>`
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
    return `<div class="lrow">`
      + `<span class="lcell lc-val">${peekChip(key, v, true)}</span>`
      + `<span class="lcell lc-meta"><span class="lrow-tag">${ci ? 'ci' : 'exact'}</span></span>`
      + `<span class="lcell lspace"></span>`
      + `<span class="lcell lc-act"><button class="btn ghost sm" data-lact="remask" data-value="${attr(v)}" title="resume masking this value">RE-MASK</button></span>`
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
      + `<span class="lcell lc-val">${peekChip(key, c.pattern, true)}</span>`
      + `<span class="lcell lrow-kind">${esc(c.entity_type)}</span>`
      + `<span class="lcell lc-meta"><span class="lrow-tag">${c.case_sensitive ? 'CS' : 'ci'}</span></span>`
      + `<span class="lcell lspace"></span>`
      + `<span class="lcell lc-act"><button class="btn ghost sm warn" data-lact="reveal" data-value="${attr(c.pattern)}" data-pattern="${attr(c.pattern)}" data-entity="${attr(c.entity_type)}">REVEAL TO MODEL</button></span>`
      + `<span class="lcell lc-act"><button class="btn ghost sm" data-lact="rm-custom" data-pattern="${attr(c.pattern)}" data-entity="${attr(c.entity_type)}">REMOVE</button></span>`
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
  const autoRowHtml = t => {
    const key = 'tok:' + t.token;
    const canReveal = t.peekable !== false && !!t.value;
    return `<div class="lrow">`
      + `<span class="lcell lrow-handle">${esc(t.token)}</span>`
      + `<span class="lcell lc-val">${peekChip(key, t.value, t.peekable)}</span>`
      + `<span class="lcell lrow-kind ${sevClass(t.entity_kind)}">${esc(t.entity_kind)}</span>`
      + `<span class="lcell lc-meta">${laneChip(t.provenance)}${t.count > 1 ? `<span class="lrow-tag">×${t.count}</span>` : ''}</span>`
      + `<span class="lcell lspace"></span>`
      + `<span class="lcell lc-act">${canReveal ? `<button class="btn ghost sm warn" data-lact="reveal" data-value="${attr(t.value)}" data-entity="${attr(t.entity_kind)}">REVEAL TO MODEL</button>` : ''}</span>`
      + `</div>`;
  };
  let autoHtml;
  if (!autoRows.length) {
    autoHtml = `<div class="empty-note">No PII auto-detected yet this session.</div>`;
  } else if (!denoise) {
    // Complete view (default): every value, in server order. Nothing folded.
    autoHtml = autoRows.map(autoRowHtml).join('');
  } else {
    // DE-NOISE: real-exposure lanes first (sorted by signal), Claude Code scaffolding folded
    // into ONE still-scanned, one-click-restorable group. Folding is display-only — the count
    // is shown and every value stays in the ledger and is still detected.
    const foldable = t => laneMeta(t.provenance).fold;
    const shown = autoRows.filter(t => !foldable(t))
      .sort((a, b) => laneMeta(b.provenance).rank - laneMeta(a.provenance).rank);
    const folded = autoRows.filter(foldable);
    autoHtml = (shown.length ? shown.map(autoRowHtml).join('')
                             : `<div class="empty-note">No content-lane PII this session — only system scaffolding below.</div>`)
      + (folded.length
          ? `<details class="ledger-fold">`
            + `<summary><span class="fold-tag">SYSTEM SCAFFOLDING</span>`
            +   `<span class="fold-sub">${folded.length} value${folded.length === 1 ? '' : 's'} masked in Claude Code framing &middot; still scanned &amp; ledgered &middot; click to show</span></summary>`
            + `<div class="ledger-rows ledger-fold-rows">${folded.map(autoRowHtml).join('')}</div>`
            + `</details>`
          : '');
  }
  $('ledgerTokens').innerHTML = autoHtml;
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
/* B3: "reveal to model" allow-lists the value, which STOPS DETECTION for it (it
   egresses unmasked AND is never re-flagged). Operators were not told that, and were
   nudged onto it to quiet ledger noise. Warn hard when the value looks like a secret. */
function isSecretClass(entity) {
  // Covers the engine's Category::Secrets kinds (incl. JWT and the auth-credential family)
  // plus financial/identity. Over-matching only adds friction to a privacy-reducing action
  // (safe direction); under-matching a credential is the risk. UNCERTAIN: ideally derived
  // from the backend Category::Secrets list so it can't drift from the engine taxonomy.
  return /KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|BANK|IBAN|CRYPTO|SSN|SWIFT|ROUTING|PRIVATE|CARD|CREDIT|PASSPORT|JWT|AUTH|BEARER|OAUTH|SESSION|COOKIE/
    .test(String(entity || '').toUpperCase());
}
function revealToModel(value, pattern, entity) {
  if (!value) return;
  const secret = isSecretClass(entity);
  const head = secret
    ? `⚠ This looks like a SECRET (${entity}). Reveal it to the model anyway?\n\n  ${value}\n\n`
    : `Reveal to the model?\n\n  ${value}\n\n`;
  const ok = window.confirm(
    head
    + `This STOPS MASKING this exact value: it is sent to the model UNMASKED from now on AND `
    + `detection is turned OFF for it (it will not be re-flagged), persisted to zlauder.local.toml. `
    + `It does not touch values masked by a config regex pattern, nor masking-exempt control/schema `
    + `keys. You can RE-MASK any time from PASSING PLAINTEXT.`
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

/* PEEK ALL master switch: flip every peekable row open/closed at once (local only). */
$('peekAllToggle').addEventListener('change', e => { peekAll = e.target.checked; renderLedger(); });

/* DE-NOISE: group the ledger by provenance lane and fold Claude Code scaffolding. Default
   OFF — the complete (overly-complete) view is the baseline; this only ever hides values
   into a still-scanned, one-click group, never drops them. Persisted locally. */
$('denoiseToggle').checked = denoise;
$('denoiseToggle').addEventListener('change', e => {
  denoise = e.target.checked;
  localStorage.setItem('zlDenoise', denoise ? '1' : '0');
  renderLedger();
});

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

// peek-values toggle (local inline display; delegated; lives inside the review pane)
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
  sessionTokens = s.session_tokens || [];
  // Server labels are authoritative — seed the cache, then derive the list from records so
  // snapshot and live 'record' frames build conversations through the SAME path.
  for (const c of (s.conversations || [])) convoLabels[c.id] = c.label;
  conversations = conversationsFromRecords();
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
// Seed the policy panel up front so `committedPolicy` is populated before the drawer is
// ever opened: the first external (CLI/other-window) policy change then both re-syncs the
// controls AND raises its confirming toast, instead of being silently absorbed as a seed.
loadPolicy();

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
    // Recompute the sidebar from records so a NEW conversation (or a fresh turn) appears
    // live on this frame — it otherwise only refreshed on the next full snapshot.
    conversations = conversationsFromRecords();
    // Augment the durable ledger live from this record's tokens — the AUTO-DETECTED
    // list otherwise only refreshes on full snapshots (per-record SSE frames carry no
    // session_tokens). Dedup by token handle; the next snapshot reconciles to the
    // authoritative server set (counts / first_seen / class). A token masked only by
    // count_tokens still lands on the next snapshot (that path emits no SSE frame).
    for (const t of (rec.tokens || [])) {
      if (!sessionTokens.some(s => s.token === t.token)) {
        // Honor the server's redaction seam: a non-peekable (secret-class) token
        // carries no plaintext and must not become peekable in the live ledger.
        const peekable = t.peekable !== false;
        // Per-record token previews carry no provenance lane (that lives on the durable
        // ledger entry); leave it undefined → "unclassified" (always shown) until the next
        // snapshot reconciles the authoritative lane.
        sessionTokens.push({ token: t.token, value: peekable ? t.value : '', entity_kind: t.entity_kind, class: t.class || 'auto_pii', peekable, count: 1, provenance: t.provenance });
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
  } else if (ev.event === 'response_progress') {
    // The model's reply is streaming back. Merge the (small) response delta onto the
    // matching record so the RESPONSE panel paints live — no full-record re-broadcast,
    // no waiting for the next turn to resend it as transcript.
    const p = ev.data;
    const rec = records.find(r => r.id === p.id);
    if (rec) {
      rec.response_preview = p.response_preview;
      rec.response_surfaces = p.response_surfaces;
      rec.response_status = p.status;
      if (selectedId === p.id) {
        // Sticky-follow the streaming tail: re-rendering rewrites #detail's innerHTML and
        // resets its scroll, so decide BEFORE the re-render whether the tail was already in
        // view. If it was (or hasn't rendered yet), scroll the fresh sentinel back into view
        // after re-render; if the operator scrolled UP to read the request, leave them be.
        const d = $('detail');
        const tail = document.getElementById('streamTail');
        let follow = true;
        if (tail) {
          const tr = tail.getBoundingClientRect(), dr = d.getBoundingClientRect();
          follow = tr.top <= dr.bottom + 160; // tail at/near the visible bottom
        }
        renderReview();
        if (follow) document.getElementById('streamTail')?.scrollIntoView({ block: 'nearest' });
      }
    }
  } else if (ev.event === 'policy') {
    // The live masking policy moved (this panel, the /zlauder:privacy CLI, or another
    // window). Re-sync the controls so the panel never drifts from the real policy.
    onPolicyEvent(ev.data);
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

/* The drawer has NO Set/Apply buttons: changing any control applies IMMEDIATELY, and
   the panel always mirrors the LIVE policy (a server `policy` SSE frame re-syncs it the
   instant /zlauder:privacy or another window moves the policy — see onPolicyEvent).
   `committedPolicy` is the last server-confirmed snapshot: the source of truth a focused
   field reverts to on Esc, and the baseline that separates our own writes from external
   ones (so an external change toasts but our own echo does not double-toast). */
let committedPolicy = null;

/* Every policy-control write (profile / threshold / category / ML) runs through ONE
   serialized promise chain, so two fast edits — e.g. category toggles that each PUT the
   WHOLE set — can never be reordered on the wire and lost-update each other. The server's
   live snapshot always re-renders the controls afterward, so ordering is the only thing
   the client must guarantee. `selfWriteInFlight` counts queued+in-flight writes; it guards
   the focusout reconcile (don't snap a control back to a not-yet-applied live value while
   our own write is in flight). */
let policyWriteChain = Promise.resolve();
let selfWriteInFlight = 0;
function policyWrite(doFetch) {
  selfWriteInFlight++;
  const run = () => doFetch().catch(() => {});   // each write owns its outcome; never break the chain
  policyWriteChain = policyWriteChain.then(run, run).finally(() => {
    selfWriteInFlight = Math.max(0, selfWriteInFlight - 1);
  });
  return policyWriteChain;
}

/* Per-write correlation id. Each write tags its request with a unique `x-zlauder-write-id`;
   the server echoes it on the resulting `policy` SSE frame. THIS tab recognizes its own
   echo (id in `pendingWids`) and suppresses the redundant external-change toast — while a
   genuinely concurrent change from the CLI or ANOTHER tab (no matching id) still toasts,
   even if it races one of our writes in flight. This is the precise origin marker the
   coarse in-flight counter couldn't be. The 30s sweep keeps the set bounded if an echo is
   never delivered (e.g. the SSE link dropped); 30s dwarfs any real round-trip. */
const pendingWids = new Set();
let widSeq = 0;
function apiWrite(path, opts = {}) {
  const wid = 'w' + (++widSeq) + '.' + Math.floor(Math.random() * 1e9).toString(36);
  pendingWids.add(wid);
  setTimeout(() => pendingWids.delete(wid), 30000);
  opts.headers = { ...(opts.headers || {}), 'x-zlauder-write-id': wid };
  return api(path, opts);
}

/* Esc inside the drawer is a TWO-STAGE key: if a policy control is focused it reverts
   that field to the live policy and unfocuses it (the in-progress edit is abandoned,
   never applied); only a second Esc (nothing focused) closes the drawer. This runs
   before the document-level closer below and stops it whenever it handled a field. */
$('policyDrawer').addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  const el = document.activeElement;
  if (el && $('policyDrawer').contains(el) && el.matches('select, input')) {
    // stopPropagation (NOT preventDefault) so the document-level closer is suppressed for
    // this Esc, while a native <select>'s own "Esc closes its open popup" still works.
    e.stopPropagation();
    revertControl(el);
    el.blur();
  }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !$('policyDrawer').hidden) closePolicy();
});

/* Capture each editable control's value as its Esc-revert baseline the moment it gains
   focus (covers a select/slider being navigated before commit). applyPolicyConfig keeps
   these baselines current after every confirmed change, so Esc always lands on the LIVE
   value, never a stale one. */
$('policyDrawer').addEventListener('focusin', e => {
  if (e.target.matches('#polProfile, #polScope, #polThresh')) e.target._baseline = e.target.value;
});

/* Close the activeElement-skip seam: applyPolicyConfig deliberately won't overwrite the
   control you're actively editing, so an external change that arrives mid-edit is held off
   that one control. The MOMENT focus leaves it, reconcile every control to the live policy
   — so "displayed == live policy" holds for any control that isn't this instant being
   edited. Skipped while one of our own writes is in flight (its result is the authoritative
   re-render, and a select's value-commit fires `change` just before `focusout`). */
$('policyDrawer').addEventListener('focusout', () => {
  if (selfWriteInFlight > 0 || !committedPolicy) return;
  applyPolicyConfig(committedPolicy);
});

/* Revert one focused control to the committed (live) policy — the Esc action. */
function revertControl(el) {
  const cfg = (committedPolicy && committedPolicy.config) || {};
  if (el === $('polThresh')) {
    const v = (el._baseline != null) ? el._baseline
            : (typeof cfg.score_threshold === 'number' ? cfg.score_threshold : el.value);
    el.value = v;
    $('polThreshVal').textContent = Number(v).toFixed(2);
    refreshDivergence();
  } else if (el === $('polProfile')) {
    el.value = cfg.profile || el._baseline || el.value;
    refreshDivergence();
  } else if (el === $('polScope')) {
    if (el._baseline != null) { el.value = el._baseline; refreshDivergence(); }
  } else if (el === $('polMlToggle')) {
    el.checked = !!(committedPolicy && committedPolicy.ml && committedPolicy.ml.enabled);
  } else if ($('polCats').contains(el)) {
    renderCategories(committedPolicy, true);
    refreshPersonalTier();
  }
}

/* ---- render the live config into the controls. Idempotent and the SINGLE place the
   panel's displayed state is set, so "what is shown == the live policy" always holds.
   Never overwrites the control the user is actively editing (activeElement); it only
   refreshes that control's Esc baseline, so an external change can't yank a field
   mid-edit yet Esc still reverts to the newest live value. ---- */
function applyPolicyConfig(snap) {
  if (!snap) return;
  committedPolicy = snap;
  const cfg = snap.config || {};
  const ml = snap.ml || {};
  const active = document.activeElement;

  // profile — render unless this control is mid-edit; the Esc baseline ALWAYS tracks the
  // LIVE value (even when the render is skipped) so Esc reverts to the newest policy.
  const liveProfile = cfg.profile || $('polProfile').value;
  if ($('polProfile') !== active) $('polProfile').value = liveProfile;
  $('polProfile')._baseline = liveProfile;

  // operator (read-only display; profiles differ on this axis — e.g. Strict now
  // tokenizes (reversible) rather than redacting, so the user must be able to SEE it)
  const op = (cfg.default_operator && cfg.default_operator.kind) || '—';
  $('polOperator').textContent = op === 'token' ? 'token (reversible)'
                              : op === 'redact' ? 'redact (irreversible)'
                              : op;

  // threshold — same rule: skip the live re-render only for the slider being dragged, but
  // keep its Esc baseline pinned to the LIVE value.
  if (typeof cfg.score_threshold === 'number') {
    const liveThresh = String(cfg.score_threshold);
    if ($('polThresh') !== active) {
      $('polThresh').value = liveThresh;
      $('polThreshVal').textContent = cfg.score_threshold.toFixed(2);
    }
    $('polThresh')._baseline = liveThresh;
  }

  // categories
  renderCategories(snap, false);

  // (modified) badge + scope-aware hint, recomputed from the displayed controls
  refreshDivergence();

  // ML
  const status = ml.status || (ml.enabled ? 'loading' : 'disabled');
  mlStatus = status;
  if ($('polMlToggle') !== active) $('polMlToggle').checked = !!ml.enabled;
  $('polMlLabel').textContent = ml.enabled ? 'enabled' : 'disabled';
  const sEl = $('polMlStatus');
  sEl.textContent = status;
  sEl.className = 'pol-ml-status ' + status;
  $('polMlModel').textContent = ml.model ? `model: ${ml.model}${ml.error ? ' — ' + ml.error : ''}` : '';

  refreshPersonalTier();
  // The protection-status line reads enabled_categories + ml status, so re-render it
  // whenever the live policy moves (the drawer is closed most of the time).
  renderProtectionStatus();
}

/* Tick the category checkboxes from a snapshot. Skips a checkbox being actively toggled
   (so a live re-sync can't fight the user's click) unless `force` — the Esc-revert wants
   the whole set restored regardless of focus. */
function renderCategories(snap, force) {
  const on = new Set(((snap && snap.config && snap.config.enabled_categories) || []));
  $('polCats').querySelectorAll('input[type=checkbox]').forEach(cb => {
    if (force || cb !== document.activeElement) cb.checked = on.has(cb.value);
  });
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

/* The default PROFILE hint — also reflects the chosen persist scope. */
function baseProfileHint() {
  const scope = $('polScope').value;
  return scope === 'session'
    ? 'Switch profile to apply instantly (threshold + categories + operator). Pick a scope to also persist.'
    : `Switch profile to apply instantly and persist to <b>${esc(scope)}</b>.`;
}

/* Re-evaluate the (modified) badge against the CURRENTLY-displayed controls (profile
   dropdown + threshold + checked categories), no server round-trip — and keep the hint
   in sync with the chosen scope. Marks the dropdown (modified) when the live policy has
   been hand-tuned away from the selected profile's preset, so switching profile (which
   resets to the preset) is never a silent surprise. */
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
    hint.innerHTML = `live policy differs from "<b>${esc(sel)}</b>" — switching profile resets your threshold/category edits.`;
    hint.classList.add('pol-warn');
  } else {
    $('polProfile').classList.remove('pol-modified');
    hint.innerHTML = baseProfileHint();
    hint.classList.remove('pol-warn');
  }
}

/* ---- live policy sync. A server `policy` SSE frame (from ANY control-plane writer —
   this panel, the /zlauder:privacy CLI, custom-mask / reveal endpoints, or another browser
   window) re-renders the panel so it is ALWAYS an accurate mirror of the live policy.
   - The dropdown/threshold/category/ML CONTROLS moving externally raises one confirming
     toast — UNLESS the frame is the echo of OUR OWN write (matched precisely by write-id,
     whose own handler already toasted). A concurrent change from the CLI / another tab is
     NOT our echo (no matching id), so it still toasts even mid-write.
   - custom-mask / allow-list (reveal) edits move the masks list and the ledger but not the
     controls; those views are refreshed silently (those ops carry their own UI feedback). */
function onPolicyEvent(snap) {
  const prev = committedPolicy;
  const wid = snap.write_id;
  const ownEcho = !!wid && pendingWids.has(wid);
  if (ownEcho) pendingWids.delete(wid);
  const controlsChanged = prev && !samePolicy(prev, snap);
  const sourcesChanged  = prev && !sameSources(prev, snap);
  applyPolicyConfig(snap);
  if (sourcesChanged) {
    if (!$('policyDrawer').hidden) loadCustomMasks();
    refreshLedgerSources();
  }
  if (controlsChanged && !ownEcho)
    policyToast('policy changed — following turns use the new policy', 'good');
}
/* Did the panel's editable CONTROLS move? (profile / threshold / categories / operator /
   ML) — drives the external-change toast. */
function samePolicy(a, b) {
  const ca = (a && a.config) || {}, cb = (b && b.config) || {};
  const ma = (a && a.ml) || {}, mb = (b && b.ml) || {};
  if ((ca.profile || '') !== (cb.profile || '')) return false;
  if (Number(ca.score_threshold) !== Number(cb.score_threshold)) return false;
  if (!sameSet(ca.enabled_categories || [], cb.enabled_categories || [])) return false;
  const oa = (ca.default_operator && ca.default_operator.kind) || 'token';
  const ob = (cb.default_operator && cb.default_operator.kind) || 'token';
  if (oa !== ob) return false;
  if (!!ma.enabled !== !!mb.enabled) return false;
  if ((ma.status || '') !== (mb.status || '')) return false;
  if ((ma.model || '') !== (mb.model || '')) return false;
  return true;
}
/* Did the masking SOURCES move? (custom-mask rules / reveal allow-list) — drives the masks
   + ledger refresh. Cheap stable-JSON compare (the server serializes both deterministically). */
function sameSources(a, b) {
  const ca = (a && a.config) || {}, cb = (b && b.config) || {};
  return JSON.stringify(ca.custom_replacements || []) === JSON.stringify(cb.custom_replacements || [])
      && JSON.stringify(ca.allow_list || {})         === JSON.stringify(cb.allow_list || {});
}

/* ---- singleton policy-change toast with the gentle re-flicker (CSS .flick). One
   reused element means rapid edits never stack a pile of toasts; each change swaps the
   text and REPLAYS the flicker, so it's unmistakable the change landed even if the toast
   was already on screen. #toasts is aria-live=polite, so the new text is announced every
   time. ---- */
let policyToastEl = null;
function policyToast(msg, kind) {
  if (policyToastEl && policyToastEl.isConnected) {
    policyToastEl.className = 'toast policy ' + (kind || 'good');
    policyToastEl.querySelector('.toast-msg').innerHTML = msg;
    policyToastEl.classList.remove('flick');
    void policyToastEl.offsetWidth;            // force reflow so the animation restarts
    policyToastEl.classList.add('flick');
    clearTimeout(policyToastEl._dismiss);
    policyToastEl._dismiss = setTimeout(dismissPolicyToast, 3600);
    return;
  }
  const tpl = $('tpl-toast').content.cloneNode(true);
  const el = tpl.querySelector('.toast');
  el.className = 'toast policy flick ' + (kind || 'good');
  el.querySelector('.toast-msg').innerHTML = msg;
  $('toasts').appendChild(el);
  policyToastEl = el;
  el._dismiss = setTimeout(dismissPolicyToast, 3600);
}
function dismissPolicyToast() {
  const el = policyToastEl;
  if (!el) return;
  el.classList.add('out');
  setTimeout(() => { el.remove(); if (policyToastEl === el) policyToastEl = null; }, 320);
}

/* ---- profile: changing the dropdown applies the preset LIVE at the chosen scope
   (threshold + categories + operator together). No Apply button. ---- */
$('polProfile').addEventListener('change', () => {
  const name = $('polProfile').value;
  const scope = $('polScope').value;
  policyWrite(() =>
    apiWrite(`/zlauder/profile/${encodeURIComponent(name)}?scope=${encodeURIComponent(scope)}`, { method: 'POST' })
      .then(r => r.ok ? r.json() : Promise.reject(new Error('profile rejected')))
      .then(snap => {
        applyPolicyConfig(snap);
        const where = snap.session_only ? 'session-only'
                    : (snap.persisted ? `persisted → ${esc(snap.persisted)}` : 'applied');
        if (snap.persist_error) policyToast(`profile <b>${esc(name)}</b> applied LIVE — following turns use it · persist failed: ${esc(snap.persist_error)}`, 'bad');
        else policyToast(`profile <b>${esc(name)}</b> — following turns use it · ${where}`, 'good');
      })
      .catch(() => { revertPanelToCommitted(); toast('profile change failed', 'bad'); }));
});

/* scope is a DESTINATION, not a policy value: changing it applies nothing now — it sets
   where the NEXT profile change is written. Just refresh the scope-aware hint. */
$('polScope').addEventListener('change', refreshDivergence);

/* ---- threshold: drag previews (input), release applies (change) ---- */
$('polThresh').addEventListener('input', e => { $('polThreshVal').textContent = Number(e.target.value).toFixed(2); refreshDivergence(); });
$('polThresh').addEventListener('change', () => {
  const v = Number($('polThresh').value);
  policyWrite(() => putConfigMerge({ score_threshold: v }, `threshold <b>${v.toFixed(2)}</b> — following turns mask at this cutoff`));
});

/* ---- categories: each toggle applies the new set immediately (serialized so two fast
   toggles can't reorder their whole-set PUTs and lost-update each other) ---- */
$('polCats').addEventListener('change', () => {
  refreshDivergence();
  refreshPersonalTier();
  const sel = [...$('polCats').querySelectorAll('input:checked')].map(cb => cb.value);
  policyWrite(() => putConfigMerge({ enabled_categories: sel }, `categories <b>${esc(sel.join(', ') || 'none')}</b> — following turns use them`));
});

/* A rejected write must leave NO trace of the rejected value: blur the focused control
   first (applyPolicyConfig deliberately won't overwrite the active element) so the
   rollback to the committed policy is total — displayed always equals the live policy. */
function revertPanelToCommitted() {
  const a = document.activeElement;
  if (a && $('policyDrawer').contains(a)) a.blur();
  applyPolicyConfig(committedPolicy);
}

/* shared merge-PUT helper. On success the server's authoritative snapshot re-renders the
   controls; on failure roll the controls back to the committed policy and surface why. */
function putConfigMerge(body, label) {
  return apiWrite('/zlauder/config', { method: 'PUT', body: JSON.stringify(body) })
    .then(r => r.ok ? r.json() : r.text().then(t => Promise.reject(new Error(t))))
    .then(snap => { applyPolicyConfig(snap); policyToast(label, 'good'); })
    .catch(err => { revertPanelToCommitted(); toast(`set failed: ${esc(err.message || 'rejected')}`, 'bad'); });
}

/* ---- ML toggle (already immediate) ---- */
$('polMlToggle').addEventListener('change', e => {
  const on = e.target.checked;
  policyWrite(() =>
    apiWrite(`/zlauder/ml/${on ? 'enable' : 'disable'}`, { method: 'POST' })
      .then(r => r.ok ? r.json() : Promise.reject(new Error('ml toggle failed')))
      .then(snap => {
        applyPolicyConfig(snap);
        policyToast(on ? 'ML enabling — following turns mask names/locations once the model is <b>ready</b>'
                       : 'ML disabled — following turns are regex-only', on ? 'good' : 'bad');
      })
      .catch(() => { e.target.checked = !on; toast('ML toggle failed', 'bad'); }));
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
