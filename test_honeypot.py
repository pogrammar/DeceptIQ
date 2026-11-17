import os
import tempfile

import pytest

os.environ["HONEYPOT_ADMIN_TOKEN"] = "test-token"

import app as hp  # noqa: E402

H = {"X-Admin-Token": "test-token"}


@pytest.fixture()
def client():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    hp.app.config["DB_PATH"] = path
    hp.bootstrap(start_active=True)
    with hp.app.test_client() as c:
        yield c
    os.remove(path)


def events(client, **params):
    r = client.get("/_hp/events", headers=H, query_string=params)
    return r.get_json()["events"]


def test_captures_ip_timestamp_url(client):
    client.get("/admin?x=1", environ_overrides={"REMOTE_ADDR": "203.0.113.7"})
    ev = events(client)[0]
    assert ev["ip"] == "203.0.113.7"
    assert ev["url"].endswith("/admin?x=1")
    assert ev["ts_utc"].endswith("+00:00")
    assert ev["method"] == "GET"


def test_decoy_looks_like_php_server(client):
    r = client.get("/")
    assert "PHP" in r.headers["X-Powered-By"]
    assert client.get("/.env").status_code == 200


def test_classification(client):
    client.get("/shell.php?cmd=whoami")
    client.get("/p.php?id=1' OR 1=1 --")
    client.get("/index.php?f=../../etc/passwd")
    client.post("/index.php?s=php://input", data="<?php system('id'); ?>")
    tags = {t for e in events(client) for t in e["tags"]}
    assert {"webshell-probe", "sql-injection", "path-traversal", "php-rce"} <= tags


def test_severity_levels(client):
    client.get("/")
    client.post("/index.php?s=php://input", data="<?php system('id'); ?>")
    sev = {e["path"]: e["severity"] for e in events(client)}
    assert sev["/"] == "low"
    assert sev["/index.php"] == "high"


def test_credentials_in_body_recorded(client):
    client.post("/wp-login.php", data={"username": "root", "password": "hunter2"})
    assert "hunter2" in events(client)[0]["body"]


def test_activation_deactivation_tracked(client):
    assert client.get("/_hp/status", headers=H).get_json()["active"] is True

    r = client.post("/_hp/deactivate", headers=H, json={"note": "patching done"})
    assert r.get_json()["active"] is False
    n_before = len(events(client))
    resp = client.get("/admin")                     # should NOT be logged
    assert resp.status_code == 503
    assert len(events(client)) == n_before

    client.post("/_hp/activate", headers=H)
    client.get("/admin")
    assert len(events(client)) == n_before + 1

    actions = [h["action"] for h in
               client.get("/_hp/state-log", headers=H).get_json()["history"]]
    assert actions == ["activated", "deactivated", "activated"]


def test_control_plane_requires_token(client):
    for path in ("/_hp/status", "/_hp/events", "/_hp/stats", "/_hp/dashboard", "/_hp/state-log"):
        assert client.get(path).status_code == 404
    assert client.post("/_hp/deactivate").status_code == 404
    assert client.get("/_hp/status", headers={"X-Admin-Token": "wrong"}).status_code == 404


def test_body_truncated(client):
    client.post("/upload.php", data="A" * 20000)
    # 20000 bytes is under the 64KB cap but must be clipped to the log limit
    assert len(events(client)[0]["body"]) == hp.MAX_BODY_LOGGED


def test_oversized_request_discarded_but_logged(client):
    r = client.post("/upload.php", data=b"B" * (hp.MAX_CONTENT_LENGTH + 10))
    assert r.status_code in (200, 413)   # must not crash
    ev = events(client)[0]
    assert "oversized-body" in ev["tags"] and ev["path"] == "/upload.php"


def test_nothing_is_executed(client):
    # The honeypot must only record, never act on attacker input.
    r = client.get("/shell.php?cmd=touch%20/tmp/pwned_by_attacker")
    assert r.status_code == 200 and r.data == b""
    assert not os.path.exists("/tmp/pwned_by_attacker")


def test_dashboard_escapes_html(client):
    client.get("/<script>alert(1)</script>")
    html = client.get("/_hp/dashboard", headers=H).data.decode()
    assert "<script>alert(1)</script>" not in html


def test_stats(client):
    client.get("/admin", environ_overrides={"REMOTE_ADDR": "198.51.100.9"})
    client.get("/admin", environ_overrides={"REMOTE_ADDR": "198.51.100.9"})
    s = client.get("/_hp/stats", headers=H).get_json()
    assert s["top_ips"][0] == {"ip": "198.51.100.9", "hits": 2}
