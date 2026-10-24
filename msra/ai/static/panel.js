/* MSRA AI panel: model selection, AI triage, verdict badges, learning insights.
 *
 * Self-contained (no framework). Everything that comes from the server - and
 * especially model output - is rendered with textContent / DOM nodes, never
 * innerHTML, so a malicious APK cannot inject markup through AI reasoning text.
 */
(function () {
  'use strict';
  if (window.__msraAiPanel) return;
  window.__msraAiPanel = true;

  // ── tiny helpers ────────────────────────────────────────────────────────
  function h(tag, attrs) {
    var el = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var kid = arguments[i];
      if (kid == null || kid === false) continue;
      el.appendChild(typeof kid === 'string' ? document.createTextNode(kid) : kid);
    }
    return el;
  }
  function icon(name) { return h('i', { class: 'fa-solid fa-' + name }); }
  function $(sel, root) { return (root || document).querySelector(sel); }
  function scanId() {
    var m = location.pathname.match(/\/scans\/([A-Za-z0-9_-]+)/);
    if (m) return m[1];
    var el = document.querySelector('.topbar[data-scan-id]');
    return el ? el.getAttribute('data-scan-id') : null;
  }
  function api(path, opts) {
    opts = opts || {};
    var init = { method: opts.method || 'GET', credentials: 'same-origin', headers: {} };
    if (opts.body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.body);
    }
    return fetch(path, init).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) { var e = new Error(j.error || ('HTTP ' + r.status)); e.status = r.status; throw e; }
        return j;
      });
    });
  }
  function money(n) { return '$' + (n || 0).toFixed(n && n < 1 ? 4 : 2); }
  function fmtTokens(n) { return n >= 1e6 ? (n / 1e6).toFixed(2) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n || 0); }
  function debounce(fn, ms) { var t; return function () { clearTimeout(t); t = setTimeout(fn, ms); }; }

  // ── styles ──────────────────────────────────────────────────────────────
  var css = [
    '.ai-btn{display:inline-flex;align-items:center;gap:6px}',
    '.ai-btn.ai-on{border-color:rgba(47,129,247,.5);color:var(--accent)}',
    '.ai-toasts{position:fixed;right:18px;bottom:18px;z-index:900;display:flex;flex-direction:column;gap:8px;max-width:360px}',
    '.ai-toast{background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;padding:10px 12px;font-size:12.5px;color:var(--text);box-shadow:0 10px 30px rgba(0,0,0,.45)}',
    '.ai-toast.err{border-left-color:#ef4444}.ai-toast.ok{border-left-color:#22c55e}.ai-toast.warn{border-left-color:#eab308}',
    '.ai-bar{height:5px;background:var(--bg3);border-radius:4px;overflow:hidden;margin-top:8px}',
    '.ai-bar>div{height:100%;background:var(--accent);transition:width .3s}',
    '.ai-ov{position:fixed;inset:0;z-index:700;background:rgba(0,0,0,.78);backdrop-filter:blur(5px);display:flex;align-items:flex-start;justify-content:center;padding:36px 16px;overflow-y:auto}',
    '.ai-modal{background:var(--bg2);border:1px solid var(--border);border-radius:12px;width:100%;max-width:820px;box-shadow:0 28px 70px rgba(0,0,0,.65)}',
    '.ai-head{display:flex;align-items:center;gap:10px;padding:18px 22px;border-bottom:1px solid var(--border)}',
    '.ai-head h2{margin:0;font-size:16px;font-weight:700;flex:1}',
    '.ai-x{background:none;border:none;color:var(--text2);font-size:16px;cursor:pointer;padding:4px 8px}',
    '.ai-body{padding:18px 22px;display:flex;flex-direction:column;gap:18px}',
    '.ai-sec h3{margin:0 0 8px;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--text2)}',
    '.ai-card{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px}',
    '.ai-pill{display:inline-block;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:10px}',
    '.ai-pill.good{background:rgba(34,197,94,.14);color:#4ade80}.ai-pill.bad{background:rgba(239,68,68,.14);color:#f87171}',
    '.ai-pill.warn{background:rgba(234,179,8,.14);color:#facc15}.ai-pill.mute{background:rgba(139,148,158,.14);color:var(--text2)}',
    '.ai-row{display:grid;grid-template-columns:190px 1fr auto;gap:10px;align-items:start;padding:10px 0;border-bottom:1px solid var(--border)}',
    '.ai-row:last-child{border-bottom:none}',
    '.ai-lbl{font-size:12.5px;font-weight:600;color:var(--text)}.ai-sub{font-size:11px;color:var(--text3);margin-top:2px}',
    '.ai-in,.ai-sel{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font-size:12.5px;font-family:inherit;box-sizing:border-box}',
    '.ai-in:focus,.ai-sel:focus{outline:none;border-color:var(--accent)}',
    '.ai-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}',
    '.ai-fld label{display:block;font-size:10.5px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:5px}',
    '.ai-foot{display:flex;align-items:center;gap:10px;padding:14px 22px;border-top:1px solid var(--border)}',
    '.ai-foot .sp{flex:1}',
    '.ai-note{font-size:11.5px;color:var(--text3);line-height:1.5}',
    '.ai-stat{display:flex;gap:18px;flex-wrap:wrap;font-size:12px;color:var(--text2)}.ai-stat b{color:var(--text)}',
    '.ai-noisy{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:12.5px}',
    '.ai-noisy:last-child{border-bottom:none}.ai-noisy code{font-size:11.5px;color:var(--text2)}',
    '.ai-badges{display:inline-flex;gap:5px;margin-left:6px;vertical-align:middle}',
    '.ai-badge{font-size:10px;font-weight:700;padding:1px 7px;border-radius:9px;white-space:nowrap}',
    '.ai-vote{padding:8px 0;border-bottom:1px solid var(--border);font-size:12.5px}.ai-vote:last-child{border-bottom:none}',
    '.ai-vote .t{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);margin-bottom:3px}',
    '.ai-rsec{margin-top:8px;font-size:12.5px}.ai-rt{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);margin-bottom:2px;cursor:default}',
    '.ai-rli{margin:2px 0}.ai-rsec code{font-size:11.5px}',
    '@media (max-width:700px){.ai-row{grid-template-columns:1fr}.ai-grid{grid-template-columns:1fr}}'
  ].join('\n');
  document.head.appendChild(h('style', { id: 'msra-ai-css', text: css }));

  // ── toasts ──────────────────────────────────────────────────────────────
  var toastBox = null;
  function toast(msg, kind, ms) {
    if (!toastBox) { toastBox = h('div', { class: 'ai-toasts' }); document.body.appendChild(toastBox); }
    var t = h('div', { class: 'ai-toast ' + (kind || '') }, msg);
    toastBox.appendChild(t);
    if (ms !== 0) setTimeout(function () { t.remove(); }, ms || 4500);
    return t;
  }

  // ── shared data ─────────────────────────────────────────────────────────
  var VERDICT = {
    true_positive: { cls: 'bad', label: 'AI: likely real' },
    false_positive: { cls: 'good', label: 'AI: likely FP' },
    uncertain: { cls: 'mute', label: 'AI: unsure' }
  };
  var findingMap = {};       // id -> {ai, fb}
  var findingsScan = null;

  function loadFindingData(force) {
    var sid = scanId();
    if (!sid) return Promise.resolve();
    if (!force && findingsScan === sid) return Promise.resolve();
    return api('/api/scans/' + sid + '/findings').then(function (d) {
      findingMap = {};
      (d.findings || []).forEach(function (f, i) {
        findingMap[f.id != null ? f.id : i + 1] = { ai: f.ai_triage || null, fb: f.rule_feedback || null, rs: f.ai_research || null };
      });
      findingsScan = sid;
    }).catch(function () { /* badges are optional */ });
  }

  // ── row badges + drawer card ────────────────────────────────────────────
  function badge(text, cls, title) {
    return h('span', { class: 'ai-badge ai-pill ' + cls, title: title || '' }, text);
  }
  function decorateRows() {
    var pills = document.querySelectorAll('[id^="tpill-"]');
    pills.forEach(function (pill) {
      var id = pill.id.slice(6);
      var info = findingMap[id];
      var host = pill.parentNode;
      if (!host) return;
      var old = host.querySelector('.ai-badges[data-for="' + id + '"]');
      var sig = info ? JSON.stringify(info) : '';
      if (old && old.getAttribute('data-sig') === sig) return;
      if (old) old.remove();
      if (!info || (!info.ai && !info.fb && !info.rs)) return;
      var wrap = h('span', { class: 'ai-badges', 'data-for': id, 'data-sig': sig });
      if (info.ai) {
        var v = VERDICT[info.ai.verdict] || VERDICT.uncertain;
        wrap.appendChild(badge(v.label + ' ' + Math.round(info.ai.confidence || 0) + '%', v.cls,
          'Verified by ' + info.ai.model + ' (' + ((info.ai.detail || {}).agree || '?') + ' verifiers agree)'));
      }
      if (info.rs) {
        var rv = VERDICT[info.rs.verdict] || VERDICT.uncertain;
        wrap.appendChild(badge(rv.label.replace('AI:', 'Research:') + ' ' + Math.round(info.rs.confidence || 0) + '%', rv.cls,
          'Investigated by ' + info.rs.model + ' (read the code, not just the snippet)'));
      }
      if (info.fb && info.fb.fp_rate >= 0.6) {
        wrap.appendChild(badge('rule: ' + info.fb.fp + '/' + info.fb.total + ' FP', 'warn',
          'Analysts marked ' + info.fb.fp + ' of ' + info.fb.total + ' findings from this rule as false positives'));
      }
      pill.insertAdjacentElement('afterend', wrap);
    });
  }

  function drawerCard(info) {
    var kids = [h('div', { class: 'ai-sec' }, h('h3', null, 'AI verification'))];
    var card = h('div', { class: 'ai-card' });
    if (info.ai) {
      var v = VERDICT[info.ai.verdict] || VERDICT.uncertain;
      card.appendChild(h('div', { style: 'display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap' },
        h('span', { class: 'ai-pill ' + v.cls, text: v.label }),
        h('span', { class: 'ai-note', text: Math.round(info.ai.confidence || 0) + '% confidence · ' +
          ((info.ai.detail || {}).agree || '?') + ' verifiers agree · ' + info.ai.model + ' · ' + money(info.ai.cost_usd) })));
      ((info.ai.detail || {}).votes || []).forEach(function (vote) {
        var vv = VERDICT[vote.verdict] || VERDICT.uncertain;
        card.appendChild(h('div', { class: 'ai-vote' },
          h('div', { class: 't' }, vote.lens.replace('_', ' ') + ' - ' + vv.label.replace('AI: ', '') + ' (' + Math.round(vote.confidence) + '%)'),
          h('div', { text: vote.reasoning || '(no reasoning)' })));
      });
      card.appendChild(h('div', { class: 'ai-note', style: 'margin-top:8px', text:
        'Advisory only: the verdict is produced by a language model reading untrusted code. Your triage decision above is what counts.' }));
    }
    if (info.fb) {
      card.appendChild(h('div', { class: 'ai-note', style: info.ai ? 'margin-top:8px' : '', text:
        'Rule track record: analysts marked ' + info.fb.fp + ' of ' + info.fb.total +
        ' findings from this rule as false positives (' + Math.round(info.fb.fp_rate * 100) + '%).' }));
    }
    kids.push(card);
    var sec = h('div', { class: 'drawer-section ai-drawer-sec' });
    kids.forEach(function (k) { sec.appendChild(k); });
    return sec;
  }
  function decorateDrawer(f) {
    var body = $('#findingDrawer .drawer-body');
    if (!body || !f) return;
    var old = body.querySelector('.ai-drawer-sec'); if (old) old.remove();
    var id = f.id != null ? f.id : null;
    var info = id != null ? findingMap[id] : null;
    var first = body.querySelector('.drawer-section');
    var sec = h('div', { class: 'drawer-section ai-drawer-sec' });
    if (info && (info.ai || info.fb)) sec.appendChild(drawerCard(info));
    if (id != null) sec.appendChild(researchBlock(id));
    if (first && first.nextSibling) body.insertBefore(sec, first.nextSibling); else body.appendChild(sec);
  }
  function wrapOpenDrawer() {
    if (typeof window.openDrawer !== 'function' || window.openDrawer.__ai) return;
    var orig = window.openDrawer;
    var wrapped = function (f) {
      var r = orig.apply(this, arguments);
      loadFindingData(false).then(function () { decorateDrawer(f); });
      return r;
    };
    wrapped.__ai = true;
    window.openDrawer = wrapped;
  }


  // ── researcher (reads the code, reasons, reports) ───────────────────────
  var researchTimers = {};
  function listBlock(title, items, render) {
    if (!items || !items.length) return null;
    var ul = h('ul', { style: 'margin:4px 0 0 18px;padding:0' });
    items.forEach(function (it) { ul.appendChild(h('li', { class: 'ai-rli' }, render ? render(it) : String(it))); });
    return h('div', { class: 'ai-rsec' }, h('div', { class: 'ai-rt', text: title }), ul);
  }
  function textBlock(title, text) {
    if (!text) return null;
    return h('div', { class: 'ai-rsec' }, h('div', { class: 'ai-rt', text: title }), h('div', { text: text }));
  }
  function renderReport(saved) {
    var r = saved.report || {}, v = VERDICT[r.verdict] || VERDICT.uncertain;
    var box = h('div', null);
    box.appendChild(h('div', { style: 'display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px' },
      h('span', { class: 'ai-pill ' + v.cls, text: v.label.replace('AI:', 'Researcher:') }),
      h('span', { class: 'ai-note', text: Math.round(saved.confidence || 0) + '% confidence · ' + saved.model + ' · ' +
        (r.steps || []).length + ' lookups · ' + money(saved.cost_usd) })));
    if (r.summary) box.appendChild(h('div', { style: 'margin-bottom:6px', text: r.summary }));
    if (r.note) box.appendChild(h('div', { class: 'ai-note', style: 'color:#facc15', text: r.note }));
    [textBlock('Root cause', r.root_cause), textBlock('Attack scenario', r.attack_scenario),
     listBlock('Preconditions', r.preconditions),
     listBlock('Evidence (checked against the real files)', r.evidence, function (e) {
       return h('span', null, h('code', { text: e.file + (e.line ? ':' + e.line : '') }), ' ',
         h('span', { class: 'ai-pill ' + (e.verified ? 'good' : 'warn'), text: e.verified ? 'verified' : 'not found' }),
         ' ' + (e.why || '')); }),
     listBlock('What I tried to disprove', r.disproof_attempts),
     textBlock('Safe way to confirm', r.poc_idea), textBlock('Remediation', r.remediation),
     listBlock('Not verified', r.unknowns), listBlock('Suggested next steps', r.next_steps),
     listBlock('Other leads noticed (unverified)', r.related_leads)
    ].forEach(function (x) { if (x) box.appendChild(x); });
    if ((r.steps || []).length) {
      var logBox = h('div', { class: 'ai-note' });
      r.steps.forEach(function (s, i) {
        var a = s.args || {};
        logBox.appendChild(h('div', { text: (i + 1) + '. ' + s.action + ' ' + (a.path || a.term || a.symbol || '') }));
      });
      box.appendChild(h('details', { class: 'ai-rsec' }, h('summary', { class: 'ai-rt', text: 'Research log' }), logBox));
    }
    box.appendChild(h('div', { class: 'ai-note', style: 'margin-top:8px', text:
      'Advisory only. The researcher read untrusted code with read-only tools; it cannot change findings, rules or your triage decision.' }));
    return box;
  }
  function researchBlock(fid) {
    var sid = scanId();
    var wrap = h('div', { class: 'ai-sec', style: 'margin-top:12px' }, h('h3', null, 'AI researcher'));
    var card = h('div', { class: 'ai-card' });
    wrap.appendChild(card);
    var base = '/api/scans/' + sid + '/findings/' + fid + '/ai-research';
    function stop() { if (researchTimers[fid]) { clearInterval(researchTimers[fid]); delete researchTimers[fid]; } }
    function paint(view) {
      card.textContent = '';
      var job = view.job || {}, saved = view.research;
      if (job.status === 'running') {
        card.appendChild(h('div', { class: 'ai-note', text: 'Investigating: step ' + (job.step || 0) + ' - ' + (job.doing || 'thinking') + ' ...' }));
        card.appendChild(h('button', { class: 'btn btn-sm', style: 'margin-top:8px', text: 'Cancel', onclick: function () {
          api(base + '/cancel', { method: 'POST' }).catch(function () {}); } }));
        return;
      }
      if (saved) card.appendChild(renderReport(saved));
      else card.appendChild(h('div', { class: 'ai-note', text:
        'Triage judges the snippet. The researcher reads the surrounding code like an analyst would: finds how it is reached, traces the data, tries to disprove it, and writes up what it found.' }));
      if (job.status === 'error') card.appendChild(h('div', { class: 'ai-note', style: 'color:#f87171', text: job.error }));
      card.appendChild(h('button', { class: 'btn btn-sm ai-btn', style: 'margin-top:10px', onclick: start },
        icon('magnifying-glass'), saved ? ' Re-investigate' : ' Investigate with AI'));
    }
    function poll() {
      stop();
      researchTimers[fid] = setInterval(function () {
        api(base).then(function (v) {
          paint(v);
          if ((v.job || {}).status !== 'running') { stop(); loadFindingData(true).then(decorateRows); }
        }).catch(stop);
      }, 1200);
    }
    function start() {
      api(base, { method: 'POST', body: {} }).then(function () {
        paint({ job: { status: 'running', step: 0, doing: 'starting' } }); poll();
      }).catch(function (e) { toast(e.message, e.status === 409 ? 'warn' : 'err', 8000); });
    }
    api(base).then(function (v) { paint(v); if ((v.job || {}).status === 'running') poll(); })
      .catch(function () { card.appendChild(h('div', { class: 'ai-note', text: 'Researcher unavailable.' })); });
    return wrap;
  }

  // ── AI triage run ───────────────────────────────────────────────────────
  var polling = null;
  function triageButtonState(running) {
    document.querySelectorAll('.ai-triage-btn').forEach(function (b) { b.disabled = !!running; });
  }
  function startTriage() {
    var sid = scanId(); if (!sid) return;
    api('/api/ai/status').then(function (st) {
      if (!st.provider.configured) {
        toast('No AI provider is configured. Open AI Settings for setup steps.', 'err', 7000);
        openSettings(); return;
      }
      var model = st.settings.models.triage, votes = st.settings.triage.votes;
      return api('/api/scans/' + sid + '/ai-triage', { method: 'POST', body: {} }).then(function (r) {
        toast('AI triage started: ' + r.total + ' findings × ' + r.votes + ' verifiers with ' + r.model, 'ok');
        watchTriage(sid);
      });
    }).catch(function (e) { toast(e.message, e.status === 409 ? 'warn' : 'err', 7000); });
  }
  function watchTriage(sid) {
    if (polling) return;
    triageButtonState(true);
    var box = h('div', { class: 'ai-toast' });
    var line = h('div', { text: 'AI triage running...' });
    var fill = h('div', { style: 'width:0%' });
    var cancel = h('button', { class: 'btn btn-sm', style: 'margin-top:8px', text: 'Cancel',
      onclick: function () { api('/api/scans/' + sid + '/ai-triage/cancel', { method: 'POST' }).catch(function () {}); } });
    box.appendChild(line); box.appendChild(h('div', { class: 'ai-bar' }, fill)); box.appendChild(cancel);
    if (!toastBox) { toastBox = h('div', { class: 'ai-toasts' }); document.body.appendChild(toastBox); }
    toastBox.appendChild(box);
    polling = setInterval(function () {
      api('/api/scans/' + sid + '/ai-triage').then(function (j) {
        var pct = j.calls_total ? Math.round(100 * j.calls_done / j.calls_total) : 0;
        fill.style.width = pct + '%';
        line.textContent = 'AI triage: ' + j.done + '/' + j.total + ' findings verified · ' + money(j.cost_usd);
        if (j.status === 'running') return;
        clearInterval(polling); polling = null; box.remove(); triageButtonState(false);
        var tally = { true_positive: 0, false_positive: 0, uncertain: 0 };
        Object.keys(j.results || {}).forEach(function (k) { tally[j.results[k].verdict] = (tally[j.results[k].verdict] || 0) + 1; });
        var msg = 'AI triage ' + j.status + ': ' + tally.true_positive + ' likely real, ' + tally.false_positive +
          ' likely false positives, ' + tally.uncertain + ' unsure · ' + money(j.cost_usd);
        if (j.stopped && j.stopped !== 'cancelled') msg += ' - stopped: ' + j.stopped;
        if (j.error) msg += ' - ' + j.error;
        toast(msg, j.status === 'done' ? 'ok' : 'warn', 9000);
        loadFindingData(true).then(decorateRows);
      }).catch(function () { clearInterval(polling); polling = null; box.remove(); triageButtonState(false); });
    }, 1000);
  }


  // ── AI vet: the researcher proves or disproves the riskiest unproven findings ──
  var vetPolling = null;
  function startVet() {
    var sid = scanId(); if (!sid) return;
    api('/api/ai/status').then(function (st) {
      if (!st.provider.configured) { toast('No AI provider is configured. Open AI Settings for setup steps.', 'err', 7000); openSettings(); return; }
      return api('/api/scans/' + sid + '/ai-vet', { method: 'POST', body: {} }).then(function (r) {
        toast('AI vetting started: the researcher will investigate ' + r.total + ' High/Critical findings that are not yet proven (' + r.model + ').', 'ok', 7000);
        watchVet(sid);
      });
    }).catch(function (e) { toast(e.message, e.status === 409 ? 'warn' : 'err', 8000); });
  }
  function watchVet(sid) {
    if (vetPolling) return;
    document.querySelectorAll('.ai-vet-btn').forEach(function (b) { b.disabled = true; });
    var box = h('div', { class: 'ai-toast' });
    var line = h('div', { text: 'AI vetting...' });
    var fill = h('div', { style: 'width:0%' });
    box.appendChild(line); box.appendChild(h('div', { class: 'ai-bar' }, fill));
    box.appendChild(h('button', { class: 'btn btn-sm', style: 'margin-top:8px', text: 'Cancel', onclick: function () {
      api('/api/scans/' + sid + '/ai-vet/cancel', { method: 'POST' }).catch(function () {}); } }));
    if (!toastBox) { toastBox = h('div', { class: 'ai-toasts' }); document.body.appendChild(toastBox); }
    toastBox.appendChild(box);
    vetPolling = setInterval(function () {
      api('/api/scans/' + sid + '/ai-vet').then(function (j) {
        fill.style.width = (j.total ? Math.round(100 * j.done / j.total) : 0) + '%';
        line.textContent = 'AI vetting: ' + j.done + '/' + j.total + ' investigated · ' + money(j.cost_usd);
        if (j.status === 'running') return;
        clearInterval(vetPolling); vetPolling = null; box.remove();
        document.querySelectorAll('.ai-vet-btn').forEach(function (b) { b.disabled = false; });
        var t = j.tally || {};
        var msg = 'AI vetting ' + j.status + ': ' + (t.true_positive || 0) + ' confirmed by reading the code, ' +
          (t.false_positive || 0) + ' disproved, ' + (t.uncertain || 0) + ' still unsure · ' + money(j.cost_usd);
        if (j.stopped && j.stopped !== 'cancelled') msg += ' - stopped: ' + j.stopped;
        if (j.error) msg += ' - ' + j.error;
        toast(msg, j.status === 'done' ? 'ok' : 'warn', 12000);
        loadFindingData(true).then(decorateRows);
      }).catch(function () { clearInterval(vetPolling); vetPolling = null; box.remove(); });
    }, 1500);
  }

  // ── settings modal ──────────────────────────────────────────────────────
  var modal = null;
  function closeSettings() { if (modal) { modal.remove(); modal = null; } document.removeEventListener('keydown', onKey); }
  function onKey(e) { if (e.key === 'Escape') closeSettings(); }

  function infoText(info) {
    if (!info) return '';
    return (info.api === 'messages' ? 'Messages API' : 'Chat-completions API') + ' · ' +
      fmtTokens(info.context) + ' context · ~$' + info.price_in + ' / $' + info.price_out + ' per 1M tokens (in/out, estimate)';
  }

  function openSettings() {
    if (modal) return;
    var body = h('div', { class: 'ai-body' }, h('div', { class: 'ai-note', text: 'Loading...' }));
    var foot = h('div', { class: 'ai-foot' });
    modal = h('div', { class: 'ai-ov', role: 'dialog', 'aria-label': 'AI settings',
      onclick: function (e) { if (e.target === modal) closeSettings(); } },
      h('div', { class: 'ai-modal' },
        h('div', { class: 'ai-head' }, icon('robot'), h('h2', { text: 'AI Settings' }),
          h('button', { class: 'ai-x', 'aria-label': 'Close', onclick: closeSettings }, icon('xmark'))),
        body, foot));
    document.body.appendChild(modal);
    document.addEventListener('keydown', onKey);

    Promise.all([api('/api/ai/status'), api('/api/ai/models'), api('/api/ai/learning').catch(function () { return null; })])
      .then(function (r) { render(body, foot, r[0], r[1], r[2]); })
      .catch(function (e) { body.textContent = ''; body.appendChild(h('div', { class: 'ai-note', text: 'Could not load AI settings: ' + e.message })); });
  }

  function render(body, foot, st, cat, learn) {
    body.textContent = ''; foot.textContent = '';
    var prov = st.provider, cfg = st.settings, usage = st.usage;
    var byId = {};
    (cat.models || []).forEach(function (m) { byId[m.id] = m; });

    // provider
    var provCard = h('div', { class: 'ai-card' },
      h('div', { style: 'display:flex;align-items:center;gap:10px;flex-wrap:wrap' },
        h('span', { class: 'ai-pill ' + (prov.configured ? 'good' : 'bad'), text: prov.configured ? 'Connected' : 'Not configured' }),
        h('b', { text: prov.kind === 'gateway' ? 'LLM gateway' : 'Anthropic API' }),
        h('span', { class: 'ai-note', text: prov.host }),
        h('span', { class: 'sp', style: 'flex:1' }),
        h('button', { class: 'btn btn-sm', text: 'Refresh models', onclick: function () {
          api('/api/ai/models?refresh=1').then(function (c2) { toast('Model list refreshed (' + (c2.models || []).length + ' models)', 'ok'); closeSettings(); openSettings(); })
            .catch(function (e) { toast(e.message, 'err'); });
        } })));
    if (!prov.configured) {
      provCard.appendChild(h('div', { class: 'ai-note', style: 'margin-top:8px', text:
        'Credentials come from the environment only (never stored by MSRA). Set ANTHROPIC_API_KEY, or MSRA_LLM_PROVIDER=bedrock (native AWS Bedrock, standard AWS credential chain), or for a Bedrock-style gateway ' +
        'set MSRA_LLM_BASE_URL and MSRA_LLM_TOKEN (optional: MSRA_LLM_AUTH_HEADER, MSRA_LLM_API_PATH, MSRA_LLM_CHAT_PATH), then restart the server.' }));
    } else if (prov.kind === 'gateway') {
      provCard.appendChild(h('div', { class: 'ai-note', style: 'margin-top:8px', text:
        'Claude models use the Messages API; other vendors (DeepSeek, Qwen, Llama, Nova, ...) are routed to chat-completions automatically.' }));
    }
    body.appendChild(h('div', { class: 'ai-sec' }, h('h3', null, 'Provider'), provCard));

    // models
    var dl = h('datalist', { id: 'ai-model-list' });
    (cat.models || []).forEach(function (m) { dl.appendChild(h('option', { value: m.id }, m.label || m.id)); });
    var inputs = {};
    var modelsCard = h('div', { class: 'ai-card' }, dl);
    Object.keys(st.features).forEach(function (feat) {
      var cur = cfg.models[feat];
      var info = h('div', { class: 'ai-sub', text: infoText(byId[cur]) });
      var input = h('input', { class: 'ai-in', list: 'ai-model-list', value: cur, spellcheck: 'false',
        'aria-label': st.features[feat].label + ' model', autocomplete: 'off' });
      inputs[feat] = input;
      var lookup = debounce(function () {
        var v = input.value.trim();
        if (byId[v]) { info.textContent = infoText(byId[v]); return; }
        if (!v) { info.textContent = ''; return; }
        api('/api/ai/model-info?model=' + encodeURIComponent(v)).then(function (i) {
          info.textContent = (i.resolved && i.resolved !== v ? 'Resolves to ' + i.resolved + ' · ' : '') + infoText(i); })
          .catch(function () { info.textContent = 'Not a valid model id'; });
      }, 300);
      input.addEventListener('input', lookup);
      if (!byId[cur]) lookup();           // aliases / custom ids: show routing + price straight away
      var result = h('span', { class: 'ai-sub' });
      var test = h('button', { class: 'btn btn-sm', text: 'Test', onclick: function () {
        result.textContent = 'testing...';
        api('/api/ai/test', { method: 'POST', body: { model: input.value.trim() } }).then(function (r) {
          if (!r.ok) { result.textContent = 'Failed: ' + r.error; return; }
          result.textContent = r.coerced ? 'Warning: provider answered with ' + r.model_returned + ' instead' :
            'OK · ' + r.ms + ' ms · ' + money(r.usd);
        }).catch(function (e) { result.textContent = 'Failed: ' + e.message; });
      } });
      modelsCard.appendChild(h('div', { class: 'ai-row' },
        h('div', null, h('div', { class: 'ai-lbl', text: st.features[feat].label }), h('div', { class: 'ai-sub', text: feat })),
        h('div', null, input, info, result),
        test));
    });
    modelsCard.appendChild(h('div', { class: 'ai-note', style: 'margin-top:8px', text:
      'Pick from the list or type any model id your provider offers. Bare tier names (sonnet, opus, haiku, fable) resolve to exact ids; ' +
      'MSRA warns if the provider silently answers with a different model. ' + (st.pricing_note || '') }));
    body.appendChild(h('div', { class: 'ai-sec' }, h('h3', null, 'Model per feature'), modelsCard));

    // triage + budget
    var votes = h('select', { class: 'ai-sel' }); [1, 2, 3, 4, 5].forEach(function (n) {
      votes.appendChild(h('option', { value: n, selected: n === cfg.triage.votes }, n + (n === 1 ? ' verifier' : ' verifiers'))); });
    var minSev = h('select', { class: 'ai-sel' }); ['Info', 'Low', 'Medium', 'High', 'Critical'].forEach(function (s) {
      minSev.appendChild(h('option', { value: s, selected: s === cfg.triage.min_severity }, s + ' and above')); });
    var maxF = h('input', { class: 'ai-in', type: 'number', min: 1, max: 200, value: cfg.triage.max_findings });
    var cap = h('input', { class: 'ai-in', type: 'number', min: 0, step: '0.5', placeholder: 'no limit',
      value: cfg.budget.usd_cap == null ? '' : cfg.budget.usd_cap });
    var rsteps = h('input', { class: 'ai-in', type: 'number', min: 2, max: 12, value: (cfg.research || {}).max_steps || 6 });
    var rusd = h('input', { class: 'ai-in', type: 'number', min: 0.05, max: 20, step: '0.05', value: (cfg.research || {}).max_usd || 0.5 });
    body.appendChild(h('div', { class: 'ai-sec' }, h('h3', null, 'AI researcher'),
      h('div', { class: 'ai-card' },
        h('div', { class: 'ai-grid' },
          h('div', { class: 'ai-fld' }, h('label', null, 'Max steps per finding'), rsteps),
          h('div', { class: 'ai-fld' }, h('label', null, 'Max spend per finding (USD)'), rusd)),
        h('div', { class: 'ai-note', style: 'margin-top:10px', text:
          'Open a finding and press "Investigate with AI". The researcher reads the decompiled code with read-only tools (files, search, callers, manifest), ' +
          'looks for what would disprove the finding, and cites file:line evidence that MSRA re-checks against the real files.' }))));
    body.appendChild(h('div', { class: 'ai-sec' }, h('h3', null, 'AI triage & budget'),
      h('div', { class: 'ai-card' },
        h('div', { class: 'ai-grid' },
          h('div', { class: 'ai-fld' }, h('label', null, 'Independent verifiers'), votes),
          h('div', { class: 'ai-fld' }, h('label', null, 'Minimum severity'), minSev),
          h('div', { class: 'ai-fld' }, h('label', null, 'Max findings per run'), maxF)),
        h('div', { class: 'ai-grid', style: 'margin-top:12px' },
          h('div', { class: 'ai-fld' }, h('label', null, 'Spend cap (USD, this server session)'), cap)),
        h('div', { class: 'ai-note', style: 'margin-top:10px', text:
          'Each finding is reviewed by N independent verifiers, each through a different lens (reachability, input control, mitigations). ' +
          'A finding is called real only if all N agree; a false-positive call needs a majority. Findings you already triaged are skipped. ' +
          'Cost per run is roughly findings × verifiers calls.' }),
        h('div', { class: 'ai-stat', style: 'margin-top:10px' },
          h('span', null, 'Calls ', h('b', { text: String(usage.calls) })),
          h('span', null, 'Tokens in/out ', h('b', { text: fmtTokens(usage.input_tokens) + ' / ' + fmtTokens(usage.output_tokens) })),
          h('span', null, 'Est. spend ', h('b', { text: money(usage.usd) })),
          h('button', { class: 'btn btn-sm', text: 'Reset', onclick: function () {
            api('/api/ai/usage/reset', { method: 'POST' }).then(function () { toast('Usage reset', 'ok'); closeSettings(); openSettings(); }); } })))));

    // learning
    if (learn) {
      var lc = h('div', { class: 'ai-card' });
      lc.appendChild(h('div', { class: 'ai-note', text: learn.decisions + ' analyst decisions recorded across all scans. ' +
        'Rules you keep marking as false positives are surfaced here, and the AI verifier is told each rule\'s track record.' }));
      if (!learn.noisy.length) lc.appendChild(h('div', { class: 'ai-note', style: 'margin-top:8px', text: 'No noisy rules yet (needs 5+ decisions at 70%+ false positives).' }));
      learn.noisy.forEach(function (r) {
        lc.appendChild(h('div', { class: 'ai-noisy' },
          h('span', { class: 'ai-pill warn', text: Math.round(r.fp_rate * 100) + '% FP' }),
          h('span', { style: 'flex:1;min-width:0' }, h('div', { text: r.title }), h('code', { text: r.rule + ' · ' + r.fp + '/' + r.total + ' marked false positive' })),
          h('button', { class: 'btn btn-sm', text: 'Disable rule', onclick: function (ev) {
            var b = ev.currentTarget;
            api('/api/rules/' + encodeURIComponent(r.rule) + '/toggle', { method: 'PATCH' }).then(function (res) {
              b.textContent = res.enabled ? 'Enabled' : 'Disabled'; b.disabled = true; })
              .catch(function (e) { toast('Could not toggle ' + r.rule + ': ' + e.message, 'err'); });
          } })));
      });
      body.appendChild(h('div', { class: 'ai-sec' }, h('h3', null, 'Learning from your triage'), lc));
    }

    foot.appendChild(h('span', { class: 'ai-note', text: 'Settings apply to new requests immediately.' }));
    foot.appendChild(h('span', { class: 'sp' }));
    foot.appendChild(h('button', { class: 'btn btn-sm', text: 'Close', onclick: closeSettings }));
    foot.appendChild(h('button', { class: 'btn btn-primary btn-sm', onclick: function () {
      var models = {};
      Object.keys(inputs).forEach(function (k) { models[k] = inputs[k].value.trim(); });
      api('/api/ai/settings', { method: 'PUT', body: {
        models: models,
        triage: { votes: parseInt(votes.value, 10), min_severity: minSev.value, max_findings: parseInt(maxF.value, 10) },
        research: { max_steps: parseInt(rsteps.value, 10), max_usd: parseFloat(rusd.value) },
        budget: { usd_cap: cap.value === '' ? null : parseFloat(cap.value) }
      } }).then(function () { toast('AI settings saved', 'ok'); closeSettings(); })
        .catch(function (e) { toast('Not saved: ' + e.message, 'err', 7000); });
    } }, icon('check'), ' Save'));
  }

  // ── topbar buttons ──────────────────────────────────────────────────────
  function injectButtons() {
    document.querySelectorAll('.topbar').forEach(function (bar) {
      if (bar.querySelector('.ai-btn')) return;
      var spacer = bar.querySelector('.topbar-spacer');
      var holder = h('span', { style: 'display:inline-flex;gap:6px;align-items:center' });
      if (bar.getAttribute('data-scan-id')) {
        holder.appendChild(h('button', { class: 'btn btn-sm ai-btn ai-vet-btn', title: 'Have the AI researcher read the code and prove or disprove the riskiest unproven findings',
          onclick: startVet }, icon('magnifying-glass'), ' AI Vet'));
        holder.appendChild(h('button', { class: 'btn btn-sm ai-btn ai-triage-btn', title: 'Verify findings with independent AI reviewers',
          onclick: startTriage }, icon('wand-magic-sparkles'), ' AI Triage'));
      }
      holder.appendChild(h('button', { class: 'btn btn-sm ai-btn', title: 'Choose models, budget and AI options',
        onclick: openSettings }, icon('robot'), ' AI'));
      if (spacer) spacer.insertAdjacentElement('afterend', holder); else bar.appendChild(holder);
    });
  }

  var refresh = debounce(function () {
    injectButtons(); wrapOpenDrawer();
    if (scanId()) loadFindingData(false).then(decorateRows);
  }, 120);
  new MutationObserver(refresh).observe(document.body, { childList: true, subtree: true });
  refresh();
  window.MSRA_AI = { openSettings: openSettings, startTriage: startTriage, startVet: startVet };
})();
