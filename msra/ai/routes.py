"""Flask blueprint for AI settings, model catalog, triage jobs and learning."""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Optional

from flask import Blueprint, jsonify, request

from . import learning, settings as S
from .client import LLMError, get_client
from .models import PRICING_NOTE, model_info, valid_model_id
from .research import ResearchSandbox, investigate
from .triage import select_findings, triage_findings

bp = Blueprint("ai", __name__)

_deps: Dict[str, Callable] = {}
_pool = None
_jobs: Dict[str, dict] = {}
_jobs_lock = threading.Lock()
_cancel: Dict[str, threading.Event] = {}
_research_jobs: Dict[tuple, dict] = {}
_research_cancel: Dict[tuple, threading.Event] = {}
_fb_cache: Dict[str, object] = {"ts": 0.0, "data": {}}
_FB_TTL = 30.0


def register(app, *, load_findings: Callable[[str], Optional[dict]],
             scan_exists: Callable[[str], bool], get_scan: Callable[[str], Optional[dict]],
             db_module, pool, scan_dir: Optional[Callable] = None) -> None:
    """Wire the blueprint to the host app's storage helpers (avoids a circular import)."""
    global _pool
    _deps.update(load_findings=load_findings, scan_exists=scan_exists, get_scan=get_scan, db=db_module,
                 scan_dir=scan_dir)
    _pool = pool
    app.register_blueprint(bp)


def feedback_stats(force: bool = False) -> dict:
    """Per-rule analyst feedback, cached briefly (it scans every scan's findings)."""
    now = time.monotonic()
    if not force and now - _fb_cache["ts"] < _FB_TTL:
        return _fb_cache["data"]
    db = _deps["db"]
    data = learning.rule_feedback(db.list_triage_rows(), _deps["load_findings"])
    _fb_cache.update(ts=now, data=data)
    return data


def invalidate_feedback() -> None:
    _fb_cache["ts"] = 0.0


def _client():
    return get_client()


def _not_configured():
    return jsonify({"error": "No AI provider configured. Set ANTHROPIC_API_KEY, or "
                             "MSRA_LLM_BASE_URL + MSRA_LLM_TOKEN for a gateway, or MSRA_LLM_PROVIDER=bedrock "
                             "with an AWS region, then restart."}), 400


# ── status / settings / catalog ─────────────────────────────────────────

@bp.route("/api/ai/status")
def ai_status():
    c = _client()
    return jsonify({"provider": c.provider.public(), "settings": S.load(),
                    "features": S.FEATURES, "usage": S.LEDGER.summary(),
                    "pricing_note": PRICING_NOTE})


@bp.route("/api/ai/models")
def ai_models():
    c = _client()
    try:
        models = c.list_models(force=request.args.get("refresh") == "1")
    except Exception as e:           # never 500 the settings dialog
        return jsonify({"models": [], "error": str(e)[:200]}), 200
    pricing = S.load().get("pricing")
    enriched = [dict(m, **model_info(m["id"], pricing, c.provider.kind)) for m in models]
    return jsonify({"models": enriched, "provider": c.provider.public(), "pricing_note": PRICING_NOTE})


@bp.route("/api/ai/model-info")
def ai_model_info():
    mid = (request.args.get("model") or "").strip()
    if not valid_model_id(mid):
        return jsonify({"error": "invalid model id"}), 400
    resolved = c_resolve(mid)
    return jsonify(dict(id=mid, resolved=resolved, **model_info(resolved, S.load().get("pricing"), _client().provider.kind)))


def c_resolve(mid: str) -> str:
    return _client().resolve(mid)


@bp.route("/api/ai/settings", methods=["GET", "PUT"])
def ai_settings():
    if request.method == "GET":
        return jsonify(S.load())
    body = request.get_json(silent=True)
    try:
        return jsonify(S.save(body))
    except (ValueError, TypeError) as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/ai/test", methods=["POST"])
def ai_test():
    c = _client()
    body = request.get_json(silent=True) or {}
    key = body.get("api_key") or None
    if not (c.provider.configured or key):
        return _not_configured()
    model = (body.get("model") or S.model_for("quick")).strip()
    if not valid_model_id(model):
        return jsonify({"ok": False, "error": "invalid model id"}), 400
    t0 = time.monotonic()
    try:
        r = c.complete(prompt="Reply with just: OK", model=model, max_tokens=16,
                       feature="quick", timeout=20, api_key=key, mask_input=False)
    except S.BudgetExceeded as e:
        return jsonify({"ok": False, "error": str(e)}), 402
    except LLMError as e:
        return jsonify({"ok": False, "error": str(e)}), 200
    return jsonify({"ok": True, "model": r.model, "model_returned": r.model_returned,
                    "coerced": r.coerced, "ms": int((time.monotonic() - t0) * 1000),
                    "usd": r.usd, "provider": c.provider.public()})


@bp.route("/api/ai/usage/reset", methods=["POST"])
def ai_usage_reset():
    S.LEDGER.reset()
    return jsonify({"ok": True})


# ── learning ───────────────────────────────────────────────────────────

@bp.route("/api/ai/learning")
def ai_learning():
    stats = feedback_stats(force=request.args.get("refresh") == "1")
    rows = sorted(stats.values(), key=lambda s: (-s["total"], s["rule"]))[:200]
    return jsonify({"rules": rows, "noisy": learning.noisy_rules(stats),
                    "decisions": sum(s["total"] for s in stats.values())})


# ── AI triage jobs ──────────────────────────────────────────────────────

def _job_view(scan_id: str) -> dict:
    with _jobs_lock:
        job = dict(_jobs.get(scan_id) or {"status": "none"})
    db = _deps["db"]
    job["results"] = {str(k): v for k, v in db.get_ai_triage_map(scan_id).items()}
    return job


@bp.route("/api/scans/<scan_id>/ai-triage", methods=["GET"])
def ai_triage_get(scan_id: str):
    if not _deps["scan_exists"](scan_id):
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(_job_view(scan_id))


@bp.route("/api/scans/<scan_id>/ai-triage", methods=["POST"])
def ai_triage_start(scan_id: str):
    if not _deps["scan_exists"](scan_id):
        return jsonify({"error": "Scan not found"}), 404
    c = _client()
    if not c.provider.configured:
        return _not_configured()
    data = _deps["load_findings"](scan_id)
    if not data or not data.get("findings"):
        return jsonify({"error": "No findings available for this scan"}), 404

    body = request.get_json(silent=True) or {}
    try:
        patch = S.validate({"triage": {k: body[k] for k in ("votes", "min_severity", "max_findings")
                                       if k in body}})
    except (ValueError, TypeError) as e:
        return jsonify({"error": str(e)}), 400
    cfg = S.load()
    opts = {**cfg["triage"], **patch.get("triage", {})}

    with _jobs_lock:
        cur = _jobs.get(scan_id)
        if cur and cur.get("status") == "running":
            return jsonify({"error": "AI triage already running for this scan"}), 409

    findings = data["findings"]
    for i, f in enumerate(findings, start=1):
        f.setdefault("id", i)
    db = _deps["db"]
    decided = {fid for fid, t in db.get_triage_map(scan_id).items()
               if t.get("status") in ("False Positive", "Confirmed", "Fixed")}
    already = set() if body.get("force") else set(db.get_ai_triage_map(scan_id))
    chosen = select_findings(findings, opts["min_severity"], opts["max_findings"], decided | already)
    if not chosen:
        return jsonify({"error": "Nothing to triage: no un-reviewed findings at or above "
                                 f"{opts['min_severity']}. Lower the minimum severity or use force."}), 400

    model = S.model_for("triage")
    pkg = (data.get("package") or "")
    stats = feedback_stats()
    cancel = threading.Event()
    _cancel[scan_id] = cancel
    job = {"status": "running", "total": len(chosen), "done": 0, "calls_done": 0,
           "calls_total": len(chosen) * opts["votes"], "model": model, "votes": opts["votes"],
           "started": time.time(), "cost_usd": 0.0, "error": None, "stopped": None}
    with _jobs_lock:
        _jobs[scan_id] = job

    def on_result(fid, res):
        db.upsert_ai_triage(scan_id, fid, res["verdict"], res["confidence"],
                            {"votes": res["votes"], "agree": res["agree"]}, res["model"], res["cost_usd"])
        with _jobs_lock:
            job["done"] += 1
            job["cost_usd"] = round(job["cost_usd"] + res["cost_usd"], 6)

    def on_progress(done, total):
        with _jobs_lock:
            job["calls_done"], job["calls_total"] = done, total

    def run():
        try:
            out = triage_findings(chosen, client=c, model=model, votes=opts["votes"], package=pkg,
                                  feedback_stats=stats, on_result=on_result, on_progress=on_progress,
                                  should_stop=cancel.is_set)
            with _jobs_lock:
                job["errors"] = out["errors"]
                job["stopped"] = out["stopped"]
                job["status"] = "cancelled" if out["stopped"] == "cancelled" else \
                    ("stopped" if out["stopped"] else "done")
        except Exception as e:                       # noqa: BLE001 - surface to the UI
            with _jobs_lock:
                job["status"], job["error"] = "error", str(e)[:300]
        finally:
            job["finished"] = time.time()
            _cancel.pop(scan_id, None)

    _pool.submit(run)
    return jsonify({"started": True, "total": len(chosen), "model": model, "votes": opts["votes"]}), 202


@bp.route("/api/scans/<scan_id>/ai-triage/cancel", methods=["POST"])
def ai_triage_cancel(scan_id: str):
    ev = _cancel.get(scan_id)
    if not ev:
        return jsonify({"error": "No AI triage running for this scan"}), 404
    ev.set()
    return jsonify({"ok": True})


# ── AI researcher (one finding, investigated by reading the code) ────────

def _find_finding(scan_id: str, finding_id: int):
    data = _deps["load_findings"](scan_id)
    for i, f in enumerate((data or {}).get("findings", []), start=1):
        if int(f.get("id") or i) == finding_id:
            return dict(f, id=finding_id), (data or {}).get("package") or ""
    return None


def _research_view(scan_id: str, finding_id: int) -> dict:
    with _jobs_lock:
        job = dict(_research_jobs.get((scan_id, finding_id)) or {"status": "none"})
    saved = _deps["db"].get_ai_research(scan_id, finding_id)
    return {"job": job, "research": saved}


@bp.route("/api/scans/<scan_id>/findings/<int:finding_id>/ai-research", methods=["GET"])
def ai_research_get(scan_id: str, finding_id: int):
    if not _deps["scan_exists"](scan_id):
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(_research_view(scan_id, finding_id))


def _research_one(scan_id: str, finding_id: int, finding: dict, pkg: str, root, client, model: str,
                  opts: dict, stats: dict, cancel: threading.Event, on_step=None) -> dict:
    """Run + persist one investigation. Shared by the single-finding and batch endpoints."""
    fb = learning.feedback_sentence(stats, learning.rule_key(finding.get("fid"), finding.get("title")))
    out = investigate(finding, client=client, model=model, package=pkg, sandbox=ResearchSandbox(root),
                      max_steps=opts["max_steps"], max_usd=opts["max_usd"], feedback_line=fb,
                      should_stop=cancel.is_set, on_step=on_step)
    rep = dict(out["report"], steps=out["steps"], stopped=out["stopped"])
    if out["stopped"] != "cancelled":
        _deps["db"].upsert_ai_research(scan_id, finding_id, rep["verdict"], rep["confidence"],
                                       rep, model, out["cost_usd"])
    return out


def _decompiled_root(scan_id: str):
    scan_dir = _deps.get("scan_dir")
    root = (scan_dir(scan_id) / "decompiled") if scan_dir else None
    return root if root is not None and root.is_dir() else None


@bp.route("/api/scans/<scan_id>/findings/<int:finding_id>/ai-research", methods=["POST"])
def ai_research_start(scan_id: str, finding_id: int):
    if not _deps["scan_exists"](scan_id):
        return jsonify({"error": "Scan not found"}), 404
    c = _client()
    if not c.provider.configured:
        return _not_configured()
    hit = _find_finding(scan_id, finding_id)
    if not hit:
        return jsonify({"error": "Finding not found"}), 404
    finding, pkg = hit
    root = _decompiled_root(scan_id)
    if root is None:
        return jsonify({"error": "The decompiled sources for this scan are not available (pruned or "
                                 "not an Android scan). Re-scan to enable the researcher."}), 409
    key = (scan_id, finding_id)
    with _jobs_lock:
        cur = _research_jobs.get(key)
        if cur and cur.get("status") == "running":
            return jsonify({"error": "The researcher is already working on this finding"}), 409
    opts = S.load()["research"]
    model = S.model_for("research")
    stats = feedback_stats()
    cancel = threading.Event()
    _research_cancel[key] = cancel
    job = {"status": "running", "step": 0, "doing": "starting", "model": model,
           "started": time.time(), "error": None}
    with _jobs_lock:
        _research_jobs[key] = job

    def on_step(n, action, args):
        with _jobs_lock:
            job["step"] = n
            job["doing"] = f"{action} {str(args.get('path') or args.get('term') or args.get('symbol') or '')[:80]}".strip()

    def run():
        try:
            out = _research_one(scan_id, finding_id, finding, pkg, root, c, model, opts, stats, cancel, on_step)
            with _jobs_lock:
                job["status"] = "cancelled" if out["stopped"] == "cancelled" else "done"
                job["stopped"] = out["stopped"]
                job["cost_usd"] = out["cost_usd"]
        except Exception as e:                       # noqa: BLE001 - surface to the UI
            with _jobs_lock:
                job["status"], job["error"] = "error", str(e)[:300]
        finally:
            job["finished"] = time.time()
            _research_cancel.pop(key, None)

    _pool.submit(run)
    return jsonify({"started": True, "model": model, "max_steps": opts["max_steps"]}), 202


# ── batch: have the researcher vet the riskiest findings nobody has proven yet ──

_vet_jobs: Dict[str, dict] = {}
_vet_cancel: Dict[str, threading.Event] = {}


def vet_candidates(findings: list, researched: set, min_severity: str, limit: int,
                   include_demoted: bool = True) -> list:
    """Highest-risk findings still unproven. Heuristic demotions (`likely_fp`) are included by default,
    ranked by their ORIGINAL severity, so the researcher can overturn a demotion: the scanned app
    controls the code the heuristics look at, so they are a hint, never the last word."""
    from .triage import severity_rank
    floor = severity_rank(min_severity)
    pool = []
    for f in findings:
        vet = (f.get("extra") or {}).get("vetting") or {}
        status = vet.get("status")
        if status == "verified" or int(f["id"]) in researched:
            continue
        if status == "likely_fp" and not include_demoted:
            continue
        sev = vet.get("original_severity") if status == "likely_fp" else None
        rank = severity_rank(sev or f.get("severity", ""))
        if rank < floor:
            continue
        pool.append((rank, f))
    pool.sort(key=lambda t: (-t[0], int(t[1]["id"])))
    return [f for _, f in pool[:limit]]


@bp.route("/api/scans/<scan_id>/ai-vet", methods=["GET"])
def ai_vet_get(scan_id: str):
    if not _deps["scan_exists"](scan_id):
        return jsonify({"error": "Scan not found"}), 404
    with _jobs_lock:
        return jsonify(dict(_vet_jobs.get(scan_id) or {"status": "none"}))


@bp.route("/api/scans/<scan_id>/ai-vet", methods=["POST"])
def ai_vet_start(scan_id: str):
    if not _deps["scan_exists"](scan_id):
        return jsonify({"error": "Scan not found"}), 404
    c = _client()
    if not c.provider.configured:
        return _not_configured()
    root = _decompiled_root(scan_id)
    if root is None:
        return jsonify({"error": "The decompiled sources for this scan are not available."}), 409
    data = _deps["load_findings"](scan_id)
    if not data or not data.get("findings"):
        return jsonify({"error": "No findings available for this scan"}), 404
    body = request.get_json(silent=True) or {}
    min_sev = body.get("min_severity", "High")
    if min_sev not in S.SEVERITIES:
        return jsonify({"error": f"min_severity must be one of {S.SEVERITIES}"}), 400
    try:
        limit = max(1, min(int(body.get("max_findings", 10)), 50))
    except (TypeError, ValueError):
        return jsonify({"error": "max_findings must be a number"}), 400
    with _jobs_lock:
        cur = _vet_jobs.get(scan_id)
        if cur and cur.get("status") == "running":
            return jsonify({"error": "AI vetting is already running for this scan"}), 409
    findings = data["findings"]
    for i, f in enumerate(findings, start=1):
        f.setdefault("id", i)
    db = _deps["db"]
    decided = {fid for fid, t in db.get_triage_map(scan_id).items()
               if t.get("status") in ("False Positive", "Confirmed", "Fixed")}
    researched = set(db.get_ai_research_summary_map(scan_id)) | decided
    chosen = vet_candidates(findings, researched, min_sev, limit, include_demoted=body.get("include_demoted", True) is not False)
    if not chosen:
        return jsonify({"error": f"Nothing to vet: every finding at {min_sev} or above is already "
                                 "verified, disproved, researched or triaged."}), 400
    pkg = data.get("package") or ""
    model = S.model_for("research")
    opts = S.load()["research"]
    stats = feedback_stats()
    cancel = threading.Event()
    _vet_cancel[scan_id] = cancel
    job = {"status": "running", "total": len(chosen), "done": 0, "cost_usd": 0.0, "model": model,
           "tally": {"true_positive": 0, "false_positive": 0, "uncertain": 0}, "stopped": None,
           "started": time.time(), "error": None}
    with _jobs_lock:
        _vet_jobs[scan_id] = job

    def run():
        try:
            for f in chosen:
                if cancel.is_set():
                    job["stopped"] = "cancelled"
                    break
                out = _research_one(scan_id, int(f["id"]), f, pkg, root, c, model, opts, stats, cancel)
                with _jobs_lock:
                    job["done"] += 1
                    job["cost_usd"] = round(job["cost_usd"] + out["cost_usd"], 6)
                    v = out["report"]["verdict"]
                    job["tally"][v] = job["tally"].get(v, 0) + 1
                if out["stopped"] and out["stopped"] != "cancelled" and (
                        "budget" in out["stopped"].lower() or "provider error" in out["stopped"]):
                    job["stopped"] = out["stopped"]
                    break
            with _jobs_lock:
                job["status"] = "cancelled" if job["stopped"] == "cancelled" else (
                    "stopped" if job["stopped"] else "done")
        except Exception as e:                       # noqa: BLE001
            with _jobs_lock:
                job["status"], job["error"] = "error", str(e)[:300]
        finally:
            job["finished"] = time.time()
            _vet_cancel.pop(scan_id, None)

    _pool.submit(run)
    return jsonify({"started": True, "total": len(chosen), "model": model}), 202


@bp.route("/api/scans/<scan_id>/ai-vet/cancel", methods=["POST"])
def ai_vet_cancel(scan_id: str):
    ev = _vet_cancel.get(scan_id)
    if not ev:
        return jsonify({"error": "No AI vetting running for this scan"}), 404
    ev.set()
    return jsonify({"ok": True})


@bp.route("/api/scans/<scan_id>/findings/<int:finding_id>/ai-research/cancel", methods=["POST"])
def ai_research_cancel(scan_id: str, finding_id: int):
    ev = _research_cancel.get((scan_id, finding_id))
    if not ev:
        return jsonify({"error": "No investigation running for this finding"}), 404
    ev.set()
    return jsonify({"ok": True})


# ── UI asset ────────────────────────────────────────────────────────────

@bp.route("/ai-assets/panel.js")
def ai_panel_js():
    from pathlib import Path
    from flask import Response
    js = (Path(__file__).parent / "static" / "panel.js").read_text(encoding="utf-8")
    return Response(js, mimetype="application/javascript", headers={"Cache-Control": "no-cache"})
