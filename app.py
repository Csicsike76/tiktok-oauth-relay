"""
TikTok OAuth + Content Posting demo server.
=====================================================================

Purpose
-------
This server exists ONLY to satisfy TikTok Developer Platform app review.
It demonstrates the complete end-to-end OAuth flow + the `video.publish`
scope (Content Posting API) on a publicly reachable URL the reviewer
can exercise.

Production posting (the daily cron) continues to use
`tiktok_daily_upload.py` and `tiktok_daily_upload_fp.py` with a
pre-obtained access token. Do NOT modify those scripts. This file is
independent.

Endpoints
---------
GET  /tiktok/auth?app=ac|fp        Redirect to TikTok authorize URL
GET  /tiktok/callback?app=...      OAuth callback (exchange code -> token)
GET  /tiktok/session?app=...       JSON: is the app connected?
POST /tiktok/post?app=...          Trigger one PULL_FROM_URL publish
GET  /tiktok/status?app=...        JSON: last 5 publish_ids + status
GET  /healthz                      Liveness probe

Environment (.env)
------------------
TIKTOK_CLIENT_KEY_AC=...
TIKTOK_CLIENT_SECRET_AC=...
TIKTOK_CLIENT_KEY_FP=...
TIKTOK_CLIENT_SECRET_FP=...
TIKTOK_REDIRECT_URI_AC=https://animalcodex.fokuszmester.com/tiktok/callback
TIKTOK_REDIRECT_URI_FP=https://forestrypro.fokuszmester.com/tiktok/callback
TIKTOK_SANDBOX=1                   # 1 = sandbox mode (default during review)
TIKTOK_SCOPES=video.publish        # minimal scope, comma separated
OAUTH_SERVER_SECRET=...random...   # Flask session secret
OAUTH_SERVER_PORT=8767

Run
---
    python tiktok_oauth_server.py

Then point an HTTPS reverse proxy (Cloudflare Tunnel / Caddy / nginx)
in front so the redirect URI is HTTPS.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
import hashlib
import base64
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests
from flask import (
    Flask,
    jsonify,
    redirect,
    request,
    session,
    abort,
)

# Force UTF-8 stdout on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
BASE = Path(__file__).resolve().parent
ENV_FILES = [BASE / ".env"]
TOKEN_STORE = BASE / "tiktok_oauth_tokens.json"
PUBLISH_LOG = BASE / "tiktok_oauth_publish_log.json"


def load_env() -> dict[str, str]:
    env: dict[str, str] = dict(os.environ)
    for ef in ENV_FILES:
        if not ef.exists():
            continue
        for ln in ef.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            env.setdefault(k.strip(), v.strip())
    return env


ENV = load_env()

SANDBOX = ENV.get("TIKTOK_SANDBOX", "1") == "1"
SCOPES = ENV.get("TIKTOK_SCOPES", "video.publish")
PORT = int(ENV.get("OAUTH_SERVER_PORT", "8767"))

# Sandbox and production share the same OAuth/Open API host; the
# difference is which client_key you use. Keep the host configurable
# anyway in case TikTok ships a sandbox-only host in the future.
TIKTOK_API_HOST = ENV.get("TIKTOK_API_HOST", "https://open.tiktokapis.com")
TIKTOK_AUTH_HOST = ENV.get("TIKTOK_AUTH_HOST", "https://www.tiktok.com")

APP_CONFIG: dict[str, dict[str, str]] = {
    "ac": {
        "name": "Animal Codex",
        "handle": "@animalcodex_app",
        "client_key": ENV.get("TIKTOK_CLIENT_KEY_AC", ""),
        "client_secret": ENV.get("TIKTOK_CLIENT_SECRET_AC", ""),
        "redirect_uri": ENV.get(
            "TIKTOK_REDIRECT_URI_AC",
            "https://animalcodex.fokuszmester.com/tiktok/callback",
        ),
        "ui_url": "https://animalcodex.fokuszmester.com/tiktok-connect.html",
    },
    "fp": {
        "name": "Forestry Pro",
        "handle": "@forestrypro_app",
        "client_key": ENV.get("TIKTOK_CLIENT_KEY_FP", ""),
        "client_secret": ENV.get("TIKTOK_CLIENT_SECRET_FP", ""),
        "redirect_uri": ENV.get(
            "TIKTOK_REDIRECT_URI_FP",
            "https://forestrypro.fokuszmester.com/tiktok/callback",
        ),
        "ui_url": "https://forestrypro.fokuszmester.com/tiktok-connect.html",
    },
}

# ---------------------------------------------------------------------
# Storage helpers (tiny JSON files; no DB needed for a review server)
# ---------------------------------------------------------------------

def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def get_token(app_id: str) -> dict[str, Any] | None:
    tokens = _load_json(TOKEN_STORE, {})
    return tokens.get(app_id)


def save_token(app_id: str, token: dict[str, Any]) -> None:
    tokens = _load_json(TOKEN_STORE, {})
    token["saved_at"] = int(time.time())
    tokens[app_id] = token
    _save_json(TOKEN_STORE, tokens)


def append_publish(app_id: str, entry: dict[str, Any]) -> None:
    log = _load_json(PUBLISH_LOG, {})
    arr = log.setdefault(app_id, [])
    arr.insert(0, entry)
    log[app_id] = arr[:25]  # keep last 25
    _save_json(PUBLISH_LOG, log)


def list_publishes(app_id: str) -> list[dict[str, Any]]:
    log = _load_json(PUBLISH_LOG, {})
    return log.get(app_id, [])


# ---------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------

def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    return verifier, challenge


# ---------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = ENV.get("OAUTH_SERVER_SECRET", secrets.token_hex(32))


def _require_app(app_id: str | None) -> dict[str, str]:
    if not app_id or app_id not in APP_CONFIG:
        abort(400, "Invalid or missing ?app= parameter (use 'ac' or 'fp')")
    cfg = APP_CONFIG[app_id]
    if not cfg["client_key"] or not cfg["client_secret"]:
        abort(
            500,
            f"Client credentials missing for {app_id}. Set TIKTOK_CLIENT_KEY_{app_id.upper()} "
            f"and TIKTOK_CLIENT_SECRET_{app_id.upper()} in .env",
        )
    return cfg


@app.route("/healthz")
def healthz():
    return jsonify({
        "ok": True,
        "sandbox": SANDBOX,
        "scopes": SCOPES,
        "apps_configured": [k for k, v in APP_CONFIG.items() if v["client_key"]],
    })


# ---------------- Static HTML — review-mode demo page ----------------
@app.route("/tiktok/connect")
def serve_connect_html():
    """Serve the reviewer-facing review-mode HTML page."""
    app_id = request.args.get("app", "ac")
    html_path = {
        "ac": BASE / "ac" / "connect.html",
        "fp": BASE / "fp" / "connect.html",
    }.get(app_id)
    if not html_path or not html_path.exists():
        abort(404, f"connect page not found for app={app_id}")
    return html_path.read_text(encoding="utf-8")


# (root / handled below; this addition removed to avoid duplicate endpoint)


# ---------------- 1) /tiktok/auth -> redirect to TikTok ---------------

@app.route("/tiktok/auth")
def auth_start():
    app_id = request.args.get("app")
    cfg = _require_app(app_id)

    state = secrets.token_urlsafe(32)
    verifier, challenge = make_pkce()
    session[f"oauth_state_{app_id}"] = state
    session[f"oauth_verifier_{app_id}"] = verifier

    params = {
        "client_key": cfg["client_key"],
        "scope": SCOPES,
        "response_type": "code",
        "redirect_uri": cfg["redirect_uri"],
        "state": state,
        # PKCE
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    authorize_url = f"{TIKTOK_AUTH_HOST}/v2/auth/authorize/?{urlencode(params)}"
    return redirect(authorize_url, code=302)


# ---------------- 2) /tiktok/callback -> exchange code ----------------

@app.route("/tiktok/callback/<app_id_path>")
def auth_callback_path(app_id_path):
    """Path-based callback (TikTok dev portal rejects query params)."""
    from flask import request as _req
    # Inject ?app= into args so the existing handler logic works
    return _auth_callback_impl(app_id_path)


@app.route("/tiktok/callback")
def auth_callback():
    return _auth_callback_impl(request.args.get("app") or request.args.get("state_app"))


def _auth_callback_impl(app_id):
    # Some redirect URIs don't carry ?app=; fall back to whichever app
    # owns the stored state.
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    err = request.args.get("error")

    if err:
        return _back_to_ui(app_id, error=err)
    if not code or not state:
        return _back_to_ui(app_id, error="missing_code_or_state")

    # Try matching state against either app if app_id is unknown
    candidates = [app_id] if app_id else list(APP_CONFIG.keys())
    matched = None
    for cand in candidates:
        if not cand:
            continue
        if session.get(f"oauth_state_{cand}") == state:
            matched = cand
            break

    if not matched:
        return _back_to_ui(app_id, error="state_mismatch")

    cfg = APP_CONFIG[matched]
    verifier = session.pop(f"oauth_verifier_{matched}", "")
    session.pop(f"oauth_state_{matched}", None)

    # Exchange code -> token
    try:
        r = requests.post(
            f"{TIKTOK_API_HOST}/v2/oauth/token/",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cache-Control": "no-cache",
            },
            data={
                "client_key": cfg["client_key"],
                "client_secret": cfg["client_secret"],
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": cfg["redirect_uri"],
                "code_verifier": verifier,
            },
            timeout=30,
        )
        j = r.json()
        if "access_token" not in j:
            return _back_to_ui(matched, error=f"token_exchange_failed:{j}")
        save_token(matched, j)
        session[f"connected_{matched}"] = True
        return _back_to_ui(matched, connected=True)
    except Exception as e:
        return _back_to_ui(matched, error=f"exception:{e}")


def _back_to_ui(app_id: str | None, connected: bool = False, error: str | None = None):
    if not app_id or app_id not in APP_CONFIG:
        # Generic landing if we don't know which UI
        return f"<h1>TikTok OAuth result</h1><p>connected={connected} error={error}</p>"
    ui = APP_CONFIG[app_id]["ui_url"]
    qs = {}
    if connected:
        qs["connected"] = "1"
    if error:
        qs["error"] = error
    return redirect(f"{ui}?{urlencode(qs)}", code=302)


# ---------------- 3) /tiktok/session -> connection status -------------

@app.route("/tiktok/session")
def session_status():
    app_id = request.args.get("app")
    _require_app(app_id)
    tok = get_token(app_id)
    if not tok:
        return jsonify({"connected": False})
    expires_in = tok.get("expires_in", 0)
    age = int(time.time()) - tok.get("saved_at", 0)
    return jsonify({
        "connected": True,
        "scope": tok.get("scope", SCOPES),
        "open_id": tok.get("open_id"),
        "token_age_seconds": age,
        "expires_in": expires_in,
        "sandbox": SANDBOX,
    })


# ---------------- 4) /tiktok/post -> publish video --------------------

@app.route("/tiktok/post", methods=["POST"])
def post_video():
    app_id = request.args.get("app")
    cfg = _require_app(app_id)
    tok = get_token(app_id)
    if not tok or not tok.get("access_token"):
        return jsonify({"error": "Not connected. Complete OAuth flow first."}), 401

    body = request.get_json(silent=True) or {}
    video_url = body.get("video_url", "").strip()
    caption = body.get("caption", "").strip()
    privacy = body.get("privacy_level", "SELF_ONLY").strip()
    if not video_url:
        return jsonify({"error": "video_url required"}), 400
    if privacy not in {"SELF_ONLY", "MUTUAL_FOLLOW_FRIENDS", "PUBLIC_TO_EVERYONE", "FOLLOWER_OF_CREATOR"}:
        privacy = "SELF_ONLY"

    # In sandbox, privacy must be SELF_ONLY for unverified domain.
    if SANDBOX:
        privacy = "SELF_ONLY"

    try:
        r = requests.post(
            f"{TIKTOK_API_HOST}/v2/post/publish/video/init/",
            headers={
                "Authorization": f"Bearer {tok['access_token']}",
                "Content-Type": "application/json; charset=UTF-8",
            },
            json={
                "post_info": {
                    "title": caption[:2200],
                    "privacy_level": privacy,
                    "disable_duet": False,
                    "disable_comment": False,
                    "disable_stitch": False,
                    "video_cover_timestamp_ms": 1000,
                },
                "source_info": {
                    "source": "PULL_FROM_URL",
                    "video_url": video_url,
                },
            },
            timeout=60,
        )
        j = r.json()
        if r.status_code != 200 or "data" not in j or "publish_id" not in j["data"]:
            return jsonify({"error": f"init failed {r.status_code}: {j}"}), 502
        publish_id = j["data"]["publish_id"]
    except Exception as e:
        return jsonify({"error": f"init exception: {e}"}), 500

    entry = {
        "publish_id": publish_id,
        "video_url": video_url,
        "caption": caption[:120],
        "privacy_level": privacy,
        "status": "PENDING",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "app": app_id,
    }
    append_publish(app_id, entry)

    # Best-effort first status poll (short, non-blocking-ish)
    try:
        time.sleep(2)
        sr = requests.post(
            f"{TIKTOK_API_HOST}/v2/post/publish/status/fetch/",
            headers={
                "Authorization": f"Bearer {tok['access_token']}",
                "Content-Type": "application/json; charset=UTF-8",
            },
            json={"publish_id": publish_id},
            timeout=15,
        )
        sj = sr.json().get("data", {})
        st = sj.get("status", "PENDING")
        entry["status"] = st
        # rewrite top-of-list entry with updated status
        log = _load_json(PUBLISH_LOG, {})
        if log.get(app_id) and log[app_id][0]["publish_id"] == publish_id:
            log[app_id][0]["status"] = st
            _save_json(PUBLISH_LOG, log)
    except Exception:
        pass

    return jsonify({"publish_id": publish_id, "status": entry["status"], "sandbox": SANDBOX})


# ---------------- 5) /tiktok/status -> last N -------------------------

@app.route("/tiktok/status")
def status_list():
    app_id = request.args.get("app")
    _require_app(app_id)
    tok = get_token(app_id)
    posts = list_publishes(app_id)

    # Refresh status for the most recent pending entries (cheap; max 3)
    if tok and tok.get("access_token"):
        for entry in posts[:3]:
            if entry.get("status") in {"PUBLISH_COMPLETE", "FAILED"}:
                continue
            try:
                sr = requests.post(
                    f"{TIKTOK_API_HOST}/v2/post/publish/status/fetch/",
                    headers={
                        "Authorization": f"Bearer {tok['access_token']}",
                        "Content-Type": "application/json; charset=UTF-8",
                    },
                    json={"publish_id": entry["publish_id"]},
                    timeout=10,
                )
                sj = sr.json().get("data", {})
                entry["status"] = sj.get("status", entry.get("status", "PENDING"))
            except Exception:
                pass
        # Persist updates
        log = _load_json(PUBLISH_LOG, {})
        log[app_id] = posts
        _save_json(PUBLISH_LOG, log)

    return jsonify({
        "app": app_id,
        "sandbox": SANDBOX,
        "posts": posts[:5],
    })


# ---------------- root / index ----------------------------------------

@app.route("/")
def index():
    return (
        "<h1>TikTok OAuth + Content Posting Demo Server</h1>"
        "<ul>"
        "<li>AC UI: <a href='https://animalcodex.fokuszmester.com/tiktok-connect.html'>animalcodex.fokuszmester.com/tiktok-connect.html</a></li>"
        "<li>FP UI: <a href='https://forestrypro.fokuszmester.com/tiktok-connect.html'>forestrypro.fokuszmester.com/tiktok-connect.html</a></li>"
        "<li>Health: <a href='/healthz'>/healthz</a></li>"
        "</ul>"
        f"<p>Sandbox mode: <b>{SANDBOX}</b> &middot; Scopes: <code>{SCOPES}</code></p>"
    )


# ---------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  TikTok OAuth + Content Posting Demo Server")
    print("=" * 60)
    print(f"  Port:        {PORT}")
    print(f"  Sandbox:     {SANDBOX}")
    print(f"  Scopes:      {SCOPES}")
    print(f"  AC redirect: {APP_CONFIG['ac']['redirect_uri']}")
    print(f"  FP redirect: {APP_CONFIG['fp']['redirect_uri']}")
    print(f"  AC key set:  {bool(APP_CONFIG['ac']['client_key'])}")
    print(f"  FP key set:  {bool(APP_CONFIG['fp']['client_key'])}")
    print("=" * 60)
    # Bind on 127.0.0.1 — front with Cloudflare Tunnel / Caddy for HTTPS.
    app.run(host="127.0.0.1", port=PORT, debug=False)
