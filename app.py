"""
Cyber Deception Module - Flask Honeypot
=======================================

A low-interaction web honeypot that impersonates an unpatched, internet-facing
PHP server (think PHP2Shell-style exposure). It NEVER executes anything an
attacker sends: every request is only *recorded* and answered with canned,
fake content.

What it records for every request while ACTIVE:
    * source IP address        * UTC timestamp
    * full URL / path / query  * HTTP method
    * User-Agent + headers     * truncated request body
    * rule-based attack tags   * severity (low / medium / high)

It also keeps an audit trail of every ACTIVATION / DEACTIVATION.

Run:
    python app.py                       # starts active on 127.0.0.1:5000
    HONEYPOT_START_ACTIVE=0 python app.py

Control API (needs header  X-Admin-Token: <token>):
    GET  /_hp/status        current state + counters
    POST /_hp/activate      turn the honeypot on
    POST /_hp/deactivate    turn the honeypot off
    GET  /_hp/events        captured requests (JSON, ?limit=&ip=&severity=)
    GET  /_hp/state-log     activation / deactivation history
    GET  /_hp/stats         top IPs, top paths, tag counts
    GET  /_hp/dashboard     simple HTML dashboard (?token=...)
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from html import escape
from urllib.parse import unquote_plus

from flask import Flask, Response, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

# --------------------------------------------------------------------------
# Configuration (all overridable by environment variables)
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("HONEYPOT_DB", os.path.join(BASE_DIR, "honeypot.db"))
HOST = os.environ.get("HONEYPOT_HOST", "127.0.0.1")  # keep local by default
PORT = int(os.environ.get("HONEYPOT_PORT", "5000"))
START_ACTIVE = os.environ.get("HONEYPOT_START_ACTIVE", "1") != "0"
TRUST_PROXY = os.environ.get("HONEYPOT_TRUST_PROXY", "0") == "1"
MAX_BODY_LOGGED = 2048          # bytes of request body stored
MAX_FIELD = 1024                # max chars for URL / UA style fields
MAX_CONTENT_LENGTH = 64 * 1024  # reject giant uploads outright

ADMIN_TOKEN = os.environ.get("HONEYPOT_ADMIN_TOKEN") or secrets.token_urlsafe(24)
TOKEN_FROM_ENV = bool(os.environ.get("HONEYPOT_ADMIN_TOKEN"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

_db_lock = threading.Lock()


# --------------------------------------------------------------------------
# Database helpers (SQLite, stdlib only)
# --------------------------------------------------------------------------
def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(app.config.get("DB_PATH", DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _db_lock, get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc      TEXT NOT NULL,
                ip          TEXT NOT NULL,
                forwarded   TEXT,
                method      TEXT NOT NULL,
                url         TEXT NOT NULL,
                path        TEXT NOT NULL,
                query       TEXT,
                user_agent  TEXT,
                headers     TEXT,
                body        TEXT,
                tags        TEXT,
                severity    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc);

            CREATE TABLE IF NOT EXISTS state_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc    TEXT NOT NULL,
                action    TEXT NOT NULL,      -- activated | deactivated
                actor_ip  TEXT,
                note      TEXT
            );
            """
        )


def current_state() -> bool:
    """Active state is whatever the last state_log row says."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT action FROM state_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return bool(row and row["action"] == "activated")


def set_state(active: bool, actor_ip: str, note: str = "") -> dict:
    action = "activated" if active else "deactivated"
    with _db_lock, get_db() as conn:
        conn.execute(
            "INSERT INTO state_log (ts_utc, action, actor_ip, note) VALUES (?,?,?,?)",
            (utcnow(), action, actor_ip, note),
        )
    return {"active": active, "action": action}


# --------------------------------------------------------------------------
# Attack classification (simple, transparent, rule-based)
# --------------------------------------------------------------------------
# (tag, regex, severity weight).  Matched against path + query + body + UA.
RULES = [
    ("webshell-probe", r"(?i)(shell|c99|r57|b374k|wso|cmd|eval-stdin)\.php", 3),
    ("php-rce", r"(?i)(php://input|allow_url_include|auto_prepend_file|"
                r"<\?php|system\(|passthru\(|shell_exec\(|base64_decode\()", 3),
    ("cmd-injection", r"(?i)(;|\||`|\$\()\s*(id|whoami|uname|cat|wget|curl|nc|bash|sh)\b", 3),
    ("sql-injection", r"(?i)(union\s+select|or\s+1=1|'\s*or\s*'|sleep\(\d+\)|"
                      r"information_schema|--\s|/\*.*\*/)", 2),
    ("path-traversal", r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|/proc/self|boot\.ini)", 2),
    ("xss", r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)", 1),
    ("sensitive-file", r"(?i)(/\.env|/\.git|/\.aws|id_rsa|wp-config|\.bak$|\.sql$|"
                       r"config\.php|backup\.zip)", 2),
    ("admin-panel-scan", r"(?i)(/admin|/phpmyadmin|/wp-login|/wp-admin|/manager/html|"
                         r"/administrator|/cpanel)", 1),
    ("known-vuln-path", r"(?i)(/cgi-bin/|/vendor/phpunit|/_ignition/|/actuator|"
                        r"/solr/|/jenkins|/boaform|/hnap1)", 2),
    ("scanner-ua", r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|"
                   r"nuclei|hydra|python-requests|curl/|go-http-client)", 1),
    ("credential-attempt", r"(?i)(passw(or)?d|pwd|passwd)=", 1),
]
_COMPILED = [(t, re.compile(p), w) for t, p, w in RULES]


def classify(haystack: str) -> tuple[list[str], str]:
    tags, score = [], 0
    for tag, rx, weight in _COMPILED:
        if rx.search(haystack):
            tags.append(tag)
            score += weight
    if score >= 3:
        sev = "high"
    elif score >= 2:
        sev = "medium"
    else:
        sev = "low"
    return tags, sev


# --------------------------------------------------------------------------
# Request capture
# --------------------------------------------------------------------------
def client_ip() -> tuple[str, str | None]:
    """Return (ip, forwarded_for). X-Forwarded-For is only trusted if enabled,
    because attackers can spoof it; we always store the raw header anyway."""
    xff = request.headers.get("X-Forwarded-For")
    if TRUST_PROXY and xff:
        return xff.split(",")[0].strip(), xff
    return request.remote_addr or "unknown", xff


def clip(value: str | None, limit: int = MAX_FIELD) -> str:
    return (value or "")[:limit]


def record_request() -> dict:
    ip, xff = client_ip()
    oversized = False
    try:
        raw_body = request.get_data(cache=True, as_text=False)[:MAX_BODY_LOGGED]
    except RequestEntityTooLarge:
        raw_body, oversized = b"", True
    body = raw_body.decode("utf-8", errors="replace")
    ua = request.headers.get("User-Agent", "")
    headers = {k: clip(v, 300) for k, v in list(request.headers.items())[:40]}

    decoded_path = unquote_plus(unquote_plus(request.full_path))  # defeat double-encoding
    haystack = " ".join([request.full_path, decoded_path, body, ua])
    tags, severity = classify(haystack)
    if oversized:
        tags.append("oversized-body")
        body = "[body exceeded size limit and was discarded]"
        if severity == "low":
            severity = "medium"

    event = {
        "ts_utc": utcnow(),
        "ip": ip,
        "forwarded": clip(xff, 300) or None,
        "method": request.method,
        "url": clip(request.url),
        "path": clip(request.path),
        "query": clip(request.query_string.decode("utf-8", "replace")),
        "user_agent": clip(ua, 400),
        "headers": json.dumps(headers),
        "body": body,
        "tags": ",".join(tags),
        "severity": severity,
    }
    with _db_lock, get_db() as conn:
        conn.execute(
            """INSERT INTO events
               (ts_utc, ip, forwarded, method, url, path, query, user_agent,
                headers, body, tags, severity)
               VALUES (:ts_utc,:ip,:forwarded,:method,:url,:path,:query,
                       :user_agent,:headers,:body,:tags,:severity)""",
            event,
        )
    app.logger.warning(
        "[HONEYPOT] %s %s %s tags=%s sev=%s",
        event["ip"], event["method"], event["url"], event["tags"] or "-", severity,
    )
    return event


# --------------------------------------------------------------------------
# Auth for control endpoints
# --------------------------------------------------------------------------
def authorized() -> bool:
    supplied = request.headers.get("X-Admin-Token") or request.args.get("token", "")
    return secrets.compare_digest(supplied, ADMIN_TOKEN)


def deny() -> Response:
    # Look like any other missing page so the control plane is not advertised.
    return Response("Not Found", status=404, mimetype="text/plain")


# --------------------------------------------------------------------------
# Control plane  (/_hp/*)
# --------------------------------------------------------------------------
@app.get("/_hp/status")
def hp_status():
    if not authorized():
        return deny()
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        last = conn.execute(
            "SELECT ts_utc, action FROM state_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return jsonify(
        active=current_state(),
        total_events=total,
        last_state_change=dict(last) if last else None,
        server_time_utc=utcnow(),
    )


@app.post("/_hp/activate")
def hp_activate():
    if not authorized():
        return deny()
    if current_state():
        return jsonify(active=True, message="already active")
    note = (request.get_json(silent=True) or {}).get("note", "manual activation")
    return jsonify(set_state(True, request.remote_addr or "unknown", note))


@app.post("/_hp/deactivate")
def hp_deactivate():
    if not authorized():
        return deny()
    if not current_state():
        return jsonify(active=False, message="already inactive")
    note = (request.get_json(silent=True) or {}).get("note", "manual deactivation")
    return jsonify(set_state(False, request.remote_addr or "unknown", note))


@app.get("/_hp/events")
def hp_events():
    if not authorized():
        return deny()
    limit = max(1, min(int(request.args.get("limit", 100)), 1000))
    clauses, params = [], []
    for col in ("ip", "severity", "method"):
        if request.args.get(col):
            clauses.append(f"{col} = ?")
            params.append(request.args[col])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?", (*params, limit)
        ).fetchall()
    events = []
    for r in rows:
        d = dict(r)
        d["headers"] = json.loads(d["headers"] or "{}")
        d["tags"] = [t for t in (d["tags"] or "").split(",") if t]
        events.append(d)
    return jsonify(count=len(events), events=events)


@app.get("/_hp/state-log")
def hp_state_log():
    if not authorized():
        return deny()
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM state_log ORDER BY id").fetchall()
    return jsonify(history=[dict(r) for r in rows], active=current_state())


def build_stats() -> dict:
    with get_db() as conn:
        top_ips = conn.execute(
            "SELECT ip, COUNT(*) hits FROM events GROUP BY ip ORDER BY hits DESC LIMIT 10"
        ).fetchall()
        top_paths = conn.execute(
            "SELECT path, COUNT(*) hits FROM events GROUP BY path ORDER BY hits DESC LIMIT 10"
        ).fetchall()
        sev = conn.execute(
            "SELECT severity, COUNT(*) n FROM events GROUP BY severity"
        ).fetchall()
        tag_rows = conn.execute("SELECT tags FROM events WHERE tags != ''").fetchall()
        total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    tag_counts: dict[str, int] = {}
    for r in tag_rows:
        for t in r["tags"].split(","):
            tag_counts[t] = tag_counts.get(t, 0) + 1
    return {
        "total_events": total,
        "top_ips": [dict(r) for r in top_ips],
        "top_paths": [dict(r) for r in top_paths],
        "severity": {r["severity"]: r["n"] for r in sev},
        "tags": dict(sorted(tag_counts.items(), key=lambda kv: -kv[1])),
    }


@app.get("/_hp/stats")
def hp_stats():
    if not authorized():
        return deny()
    return jsonify(build_stats())


@app.get("/_hp/dashboard")
def hp_dashboard():
    if not authorized():
        return deny()
    stats = build_stats()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT ts_utc, ip, method, url, tags, severity FROM events ORDER BY id DESC LIMIT 50"
        ).fetchall()
        history = conn.execute(
            "SELECT ts_utc, action, actor_ip, note FROM state_log ORDER BY id DESC LIMIT 10"
        ).fetchall()
    state = "ACTIVE" if current_state() else "INACTIVE"
    color = "#1a7f37" if state == "ACTIVE" else "#b42318"

    def table(headers, data):
        head = "".join(f"<th>{h}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in row) + "</tr>"
            for row in data
        )
        return f"<table><tr>{head}</tr>{body}</table>"

    html = f"""<!doctype html><meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<title>Honeypot Dashboard</title>
<style>
 body{{font:14px system-ui,sans-serif;margin:24px;background:#0f1419;color:#e6edf3}}
 h1{{margin:0 0 4px}} h2{{margin-top:28px;font-size:16px;color:#9db1c5}}
 .badge{{display:inline-block;padding:2px 10px;border-radius:12px;background:{color};color:#fff;font-weight:600}}
 table{{border-collapse:collapse;width:100%;margin-top:8px}}
 th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid #263241;word-break:break-all}}
 th{{color:#9db1c5;font-weight:600}} .cards{{display:flex;gap:16px;margin-top:12px}}
 .card{{background:#18212b;padding:12px 18px;border-radius:8px}} .n{{font-size:24px;font-weight:700}}
</style>
<h1>Cyber Deception: Honeypot <span class="badge">{state}</span></h1>
<div class="cards">
 <div class="card"><div class="n">{stats['total_events']}</div>total events</div>
 <div class="card"><div class="n">{stats['severity'].get('high',0)}</div>high severity</div>
 <div class="card"><div class="n">{len(stats['top_ips'])}</div>distinct top IPs</div>
</div>
<h2>Recent events</h2>
{table(['Time (UTC)','IP','Method','URL','Tags','Severity'], [tuple(r) for r in rows])}
<h2>Activation history</h2>
{table(['Time (UTC)','Action','By IP','Note'], [tuple(r) for r in history])}
<h2>Top attacker IPs</h2>
{table(['IP','Hits'], [(r['ip'], r['hits']) for r in stats['top_ips']])}
<h2>Attack tags</h2>
{table(['Tag','Count'], list(stats['tags'].items()))}
"""
    return Response(html, mimetype="text/html")


# --------------------------------------------------------------------------
# Decoy surface
# --------------------------------------------------------------------------
FAKE_HEADERS = {
    "Server": "Apache/2.4.29 (Ubuntu)",          # deliberately "outdated"
    "X-Powered-By": "PHP/7.2.34",
}

LOGIN_PAGE = """<!doctype html><html><head><title>Admin Login</title></head>
<body style="font-family:sans-serif;max-width:340px;margin:80px auto">
<h2>Control Panel</h2>
<form method="post"><input name="username" placeholder="username"><br><br>
<input name="password" type="password" placeholder="password"><br><br>
<button>Sign in</button></form>{msg}</body></html>"""

FAKE_ENV = "APP_ENV=production\nDB_HOST=10.0.0.5\nDB_USER=app\nDB_PASS=Winter2019!\nAPI_KEY=hp-decoy-0000\n"
FAKE_PASSWD = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"


def decoy_response() -> Response:
    path = request.path.lower()

    if path in ("/", "/index.php", "/index.html"):
        body = "<html><head><title>Company Portal</title></head><body><h1>Company Portal</h1><p>Welcome. <a href='/admin'>Admin</a></p></body></html>"
        resp = Response(body, mimetype="text/html")
    elif path.startswith(("/admin", "/wp-login", "/wp-admin", "/login", "/phpmyadmin", "/administrator")):
        msg = ""
        if request.method == "POST":
            msg = "<p style='color:#b00'>Invalid username or password.</p>"
        resp = Response(LOGIN_PAGE.format(msg=msg), mimetype="text/html")
    elif path.endswith("/.env"):
        resp = Response(FAKE_ENV, mimetype="text/plain")
    elif "etc/passwd" in path or "etc/passwd" in request.full_path.lower():
        resp = Response(FAKE_PASSWD, mimetype="text/plain")
    elif path.endswith(".php"):
        # Pretend the (nonexistent) webshell/script ran and returned nothing useful.
        resp = Response("", status=200, mimetype="text/html")
    elif path == "/robots.txt":
        resp = Response("User-agent: *\nDisallow: /admin\nDisallow: /backup\n", mimetype="text/plain")
    else:
        resp = Response("<h1>404 Not Found</h1>", status=404, mimetype="text/html")

    for k, v in FAKE_HEADERS.items():
        resp.headers[k] = v
    return resp


def inactive_response() -> Response:
    # Generic, uninformative reply while the honeypot is switched off.
    return Response("Service Unavailable", status=503, mimetype="text/plain")


@app.route("/", defaults={"subpath": ""},
           methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.route("/<path:subpath>",
           methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def catch_all(subpath):
    if not current_state():
        return inactive_response()
    record_request()
    return decoy_response()


@app.errorhandler(413)
def too_large(_):
    if current_state():
        record_request()
    return Response("Payload Too Large", status=413)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def bootstrap(start_active: bool | None = None) -> None:
    """Create tables and make sure a first state row exists."""
    init_db()
    wanted = START_ACTIVE if start_active is None else start_active
    if current_state() != wanted:
        set_state(wanted, "local", "startup")
    elif not _has_any_state():
        set_state(wanted, "local", "startup")


def _has_any_state() -> bool:
    with get_db() as conn:
        return conn.execute("SELECT 1 FROM state_log LIMIT 1").fetchone() is not None


if __name__ == "__main__":
    bootstrap()
    print("=" * 62)
    print(f" Honeypot listening on http://{HOST}:{PORT}")
    print(f" State at start : {'ACTIVE' if current_state() else 'INACTIVE'}")
    print(f" Database       : {DB_PATH}")
    if TOKEN_FROM_ENV:
        print(" Admin token    : (from HONEYPOT_ADMIN_TOKEN)")
    else:
        print(f" Admin token    : {ADMIN_TOKEN}   (random, this run only)")
    print(f" Dashboard      : http://{HOST}:{PORT}/_hp/dashboard?token=<token>")
    print("=" * 62)
    # debug=False: the Werkzeug debugger would be a real RCE hole on a honeypot host.
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
