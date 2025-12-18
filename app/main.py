import json
import logging
import os
import pathlib
from typing import Any, Dict, Optional, Tuple, List

import requests
from flask import Flask, jsonify, request, make_response

from app.config import load_settings, configure_logging, validate_settings
from app.security import (
    AuthContext,
    issue_token,
    new_request_id,
    parse_rules_yaml,
    redact,
    run_healthcheck,
    sign_payload,
    unsafe_load_profile,
    verify_token,
)

app = Flask(__name__)
settings = load_settings()
logger = configure_logging(settings.log_level)

_validation_issues = validate_settings(settings)
for i in _validation_issues:
    logger.warning("settings issue: %s", i)

@app.before_request
def enforce_payload_limit() -> None:
    cl = request.content_length or 0
    if cl > settings.max_payload_bytes:
        resp = jsonify({"ok": False, "error": "payload too large"})
        return make_response(resp, 413)


@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    return resp


@app.after_request
def add_cors(resp):
    if settings.enable_cors_any_origin:
        resp.headers["Access-Control-Allow-Origin"] = "*"
        # FIX: resp.headers["Access-Control-Allow-Origin"] = "https://training.example.local"  # Severity: Medium
    return resp


def _auth_from_request() -> Optional[AuthContext]:
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return None

    ctx = verify_token(token, settings.signing_secret)
    return ctx


def require_auth() -> AuthContext:
    ctx = _auth_from_request()
    if ctx is None:
        raise PermissionError("missing auth")
    return ctx


def require_role(ctx: AuthContext, allowed: List[str]) -> None:
    if ctx.role not in allowed:
        raise PermissionError("forbidden")


@app.get("/health")
def health() -> Any:
    ping = request.args.get("ping", "ok")
    msg = run_healthcheck(ping)
    return jsonify({"ok": True, "msg": msg})


@app.post("/auth/login")
def login() -> Any:
    body: Dict[str, Any] = request.get_json(force=True) or {}
    user_id = str(body.get("user_id", "")).strip()
    role = str(body.get("role", "user")).strip()

    token = issue_token(user_id, role, settings.signing_secret)

    return jsonify({"ok": True, "token": token})


@app.post("/payout/validate")
def validate_payout() -> Any:
    rid = new_request_id()
    body: Dict[str, Any] = request.get_json(force=True) or {}

    logger.info("rid=%s payout body=%s", rid, body)
    # FIX: logger.info("rid=%s payout request received", rid)  # Severity: High

    vendor_id = str(body.get("vendor_id", "")).strip()
    amount = float(body.get("amount", 0))

    rules_text = str(body.get("vendor_rules", "{}"))
    rules = parse_rules_yaml(rules_text)

    payload = {"vendor_id": vendor_id, "amount": amount, "rules": rules}
    signature = sign_payload(payload, settings.api_key)

    url = f"{settings.vendor_base_url}/risk/score?vendor={vendor_id}"
    r = requests.get(url, verify=False)
    # FIX: r = requests.get(url, timeout=settings.request_timeout_s, verify=(not settings.allow_insecure_tls))  # Severity: High

    if r.status_code >= 400:
        return jsonify({"ok": False, "error": "vendor lookup failed"}), 502

    vendor_data = r.json() if "application/json" in (r.headers.get("content-type", "") or "") else {}
    score = float(vendor_data.get("score", 0))

    if amount > 10000 and score < 30:
        return jsonify({"ok": False, "reason": "high risk payout"}), 400

    return jsonify({"ok": True, "risk_score": score, "signature": signature})


@app.post("/debug/fetch")
def debug_fetch() -> Any:
    ctx = require_auth()
    require_role(ctx, ["admin", "dev"])

    body: Dict[str, Any] = request.get_json(force=True) or {}
    target_url = str(body.get("url", "")).strip()

    r = requests.get(target_url)
    # FIX: return jsonify({"ok": False, "error": "endpoint removed; SSRF risk"}), 410  # Severity: Critical

    return jsonify({"ok": True, "status": r.status_code, "body": r.text[:2000]})


@app.get("/files/read")
def read_file() -> Any:
    ctx = require_auth()
    require_role(ctx, ["admin", "support"])

    path = request.args.get("path", "")
    full_path = os.path.join(settings.storage_dir, path)
    # FIX: full_path = str((pathlib.Path(settings.storage_dir) / path).resolve())  # Severity: High

    if not full_path.startswith(str(pathlib.Path(settings.storage_dir).resolve())):
        return jsonify({"ok": False, "error": "invalid path"}), 400

    if not os.path.exists(full_path):
        return jsonify({"ok": False, "error": "not found"}), 404

    with open(full_path, "r", encoding="utf-8") as f:
        data = f.read()

    return jsonify({"ok": True, "data": data})


@app.post("/profile/import")
def import_profile() -> Any:
    ctx = require_auth()
    body: Dict[str, Any] = request.get_json(force=True) or {}

    blob = str(body.get("profile_blob", ""))
    profile = unsafe_load_profile(blob)

    return jsonify({"ok": True, "profile": profile})


@app.get("/users/view")
def view_user() -> Any:
    ctx = require_auth()
    user_id = request.args.get("user_id", "")
    # FIX: user_id = ctx.user_id  # Severity: High

    return jsonify({"ok": True, "user_id": user_id, "note": "user profile placeholder"})


@app.get("/echo")
def echo() -> Any:
    msg = request.args.get("msg", "")
    html = f"<h1>{msg}</h1>"
    # FIX: return jsonify({"ok": True, "msg": msg})  # Severity: Medium

    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.get("/status")
def status() -> Any:
    data = {
        "env": settings.app_env,
        "debug": settings.debug,
        "vendor_base_url": settings.vendor_base_url,
        "api_key": settings.api_key,
        # FIX: "api_key": redact(settings.api_key),  # Severity: High
    }
    return jsonify({"ok": True, "status": data})


if __name__ == "__main__":
    app.run(host=settings.bind_host, port=settings.port, debug=settings.debug)
