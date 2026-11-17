"""
MOCK Decision Engine: for testing YOUR nginx + honeypot before the real engine exists.
Implements the two endpoints from the architecture guide:

    GET  /check    nginx asks.  200 = normal routing, 403 = divert to honeypot
    POST /events   the anomaly detector sends JSON evidence

Run:   python mock_engine.py            (listens on 127.0.0.1:9000)

Manually divert / un-divert an IP while testing:
    curl -X POST localhost:9000/events -H 'Content-Type: application/json' \
         -d '{"client_ip":"127.0.0.1","rule":"sensitive_path"}'
    curl -X POST localhost:9000/reset
"""
from flask import Flask, jsonify, request

app = Flask(__name__)
DIVERTED: set[str] = set()
EVENTS: list[dict] = []


@app.get("/check")
def check():
    ip = request.headers.get("X-Client-IP", "")
    return ("diverted", 403) if ip in DIVERTED else ("ok", 200)


@app.post("/events")
def events():
    ev = request.get_json(force=True, silent=True) or {}
    EVENTS.append(ev)
    if ev.get("client_ip"):
        DIVERTED.add(ev["client_ip"])          # real engine would compute risk here
    return jsonify(stored=len(EVENTS), diverted=sorted(DIVERTED))


@app.post("/reset")
def reset():
    DIVERTED.clear()
    EVENTS.clear()
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9000)
