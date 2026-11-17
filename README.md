# Cyber Deception Module: Flask Honeypot

Part of **Track 2: Cybersecurity, Cryptography & Network Intelligence**.
Problem: the gap between vulnerability discovery (e.g. PHP2Shell-style bugs on
internet-facing servers) and remediation. While patches are being rolled out,
this honeypot **detects ongoing exploitation and records attacker behaviour**.

## 1. What is a honeypot? (for the slides)

A honeypot is a **decoy system with no legitimate users**. Because nobody real
should ever touch it, *every* request is suspicious, so there are almost no
false positives.

| Type | Interaction | Example |
|---|---|---|
| Low-interaction | Emulates services, canned replies | **This project** |
| Medium-interaction | Emulates OS-level behaviour | Cowrie (SSH) |
| High-interaction | A real, instrumented system | Research honeynets |

**Why it helps during the patching gap**
- Early warning: scanners and exploit kits hit the decoy before real assets.
- Attacker intel: IPs, tools (User-Agent), payloads, targeted paths.
- Distraction: attackers burn time on fake targets.
- Evidence: timestamped logs for incident response.

## 2. What it does

| Requirement | Implementation |
|---|---|
| Simple isolated Flask server | `app.py`: binds to `127.0.0.1` by default, no code execution, debug off, 64 KB request cap |
| Capture suspicious requests | Catch-all route for every path and method; fake PHP server (Apache 2.4.29, PHP 7.2) with fake `/admin`, `/wp-login.php`, `/.env`, `/etc/passwd`, webshell paths |
| Record IP, timestamp, URL | SQLite `events` table: `ip`, `ts_utc` (UTC, ms), `url`, `path`, `query`, `method`, User-Agent, headers, body (first 2 KB) |
| Track activation / deactivation | SQLite `state_log` table (`activated` / `deactivated`, time, who, note). State survives restarts. Inactive = replies `503` and logs nothing |
| Bonus: threat detection | 11 transparent regex rules tag requests (webshell probe, PHP RCE, SQLi, path traversal, XSS, sensitive-file, admin scan, scanner UA, ...) and score severity low / medium / high |

## 3. Run it

```bash
pip install -r requirements.txt
python app.py                                  # prints a random admin token
# or choose your own:
HONEYPOT_ADMIN_TOKEN=mysecret python app.py
```

Open the dashboard: `http://127.0.0.1:5000/_hp/dashboard?token=<token>`

Generate demo traffic (local only):

```bash
python simulate_attacker.py
```

Run tests: `python -m pytest -q`

### Control API (header `X-Admin-Token: <token>`)

```bash
T=mysecret
curl -H "X-Admin-Token: $T" localhost:5000/_hp/status
curl -X POST -H "X-Admin-Token: $T" localhost:5000/_hp/deactivate
curl -X POST -H "X-Admin-Token: $T" -H "Content-Type: application/json" \
     -d '{"note":"patch deployed"}' localhost:5000/_hp/activate
curl -H "X-Admin-Token: $T" "localhost:5000/_hp/events?severity=high&limit=20"
curl -H "X-Admin-Token: $T" localhost:5000/_hp/state-log
curl -H "X-Admin-Token: $T" localhost:5000/_hp/stats
```

Wrong or missing token returns a plain `404`, so the control plane is not advertised.

### Config (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `HONEYPOT_HOST` | `127.0.0.1` | Bind address |
| `HONEYPOT_PORT` | `5000` | Port (DeceptIQ plan: honeypot = 5000) |
| `HONEYPOT_DB` | `./honeypot.db` | SQLite file |
| `HONEYPOT_ADMIN_TOKEN` | random each run | Control-plane token |
| `HONEYPOT_START_ACTIVE` | `1` | `0` = start deactivated |
| `HONEYPOT_TRUST_PROXY` | `0` | `1` = use `X-Forwarded-For` as the IP (only behind your own proxy) |

## 4. Safety / isolation design

- **Never executes attacker input.** Webshell paths return an empty 200. Nothing is `eval`'d, written to disk, or run.
- **Fake data only**: the `.env` and `/etc/passwd` contents are invented.
- **Debug mode off** (the Werkzeug debugger would be a real RCE hole).
- **Bounded storage**: body clipped to 2 KB, URL / UA clipped, oversized uploads discarded and tagged.
- **Dashboard output HTML-escaped**, so attacker-supplied strings can't attack the analyst (stored XSS).
- **Spoof-resistant IPs**: `X-Forwarded-For` is stored but only trusted when explicitly enabled.
- For a real deployment, run it in a container or VM / separate VLAN with no route to production, behind a reverse proxy, with no real credentials on the host.

## 5. Data model

```
events(id, ts_utc, ip, forwarded, method, url, path, query,
       user_agent, headers, body, tags, severity)
state_log(id, ts_utc, action, actor_ip, note)
```

## 6. Integration with the rest of the project

- Teammates can pull `GET /_hp/events` (JSON) to feed asset-impact analysis or ML anomaly detection.
- Attacker IPs in `/_hp/stats` can seed a blocklist or firewall rule.
- Deactivate the honeypot once the real patch is verified, and the `state_log` shows the full exposure window.

## 7. Limitations (be upfront with judges)

- Low-interaction: a skilled attacker can fingerprint it.
- Rule-based tagging catches known patterns only (an ML layer could extend it).
- Single node, SQLite storage; fine for a prototype, not for internet-scale volume.
