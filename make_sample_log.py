"""
Make a SAMPLE deceptiq.jsonl for the anomaly-detector teammate (same format Nginx writes).

Contains normal traffic plus the four patterns the detector must find:
  1. request spike        (one IP, many requests in a 60 s window)
  2. burst of 404s        (scanner guessing paths)
  3. sensitive paths      (/.env, /.git/config, /wp-login.php ...)
  4. path traversal       (../../etc/passwd)
and some route="honeypot" rows (traffic after diversion; detector should ignore these).

  python make_sample_log.py                         -> writes sample_deceptiq.jsonl
  python make_sample_log.py --replay live.jsonl     -> APPENDS the lines one by one,
        slowly, to live.jsonl, to test a detector that "tails" a file like Nginx would.
"""
import argparse
import json
import random
import time
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))


def row(ts, ip, method, uri, status, rt, route="real"):
    return {
        "timestamp": ts.isoformat(timespec="seconds"),
        "client_ip": ip,
        "method": method,
        "uri": uri,
        "status": status,
        "request_time": round(rt, 3),
        "route": route,
    }


def build(seed=7):
    rnd = random.Random(seed)
    start = datetime.now(IST).replace(microsecond=0) - timedelta(minutes=5)
    rows = []

    # --- normal users: a few requests each, spread over 5 minutes
    pages = ["/", "/about", "/products", "/products/42", "/contact", "/static/app.css"]
    for ip in ["192.0.2.15", "192.0.2.16", "192.0.2.17", "198.51.100.4"]:
        for _ in range(8):
            t = start + timedelta(seconds=rnd.randint(0, 290))
            rows.append(row(t, ip, "GET", rnd.choice(pages), 200, rnd.uniform(0.002, 0.04)))

    # --- 1. request spike: 120 requests from one IP within ~40 s
    t0 = start + timedelta(seconds=120)
    for i in range(120):
        rows.append(row(t0 + timedelta(seconds=i * 0.33), "203.0.113.50", "GET",
                        "/products", 200, rnd.uniform(0.001, 0.02)))

    # --- 2. burst of 404s: scanner guessing pages
    t0 = start + timedelta(seconds=60)
    for i in range(30):
        rows.append(row(t0 + timedelta(seconds=i), "203.0.113.77", "GET",
                        f"/page{i}.php", 404, 0.002))

    # --- 3. sensitive paths
    t0 = start + timedelta(seconds=200)
    for i, uri in enumerate(["/.env", "/.git/config", "/wp-login.php",
                             "/phpmyadmin/", "/backup.zip", "/admin", "/config.php"]):
        rows.append(row(t0 + timedelta(seconds=i), "203.0.113.99", "GET", uri,
                        404 if i % 2 == 0 else 200, 0.003))

    # --- 4. path traversal
    t0 = start + timedelta(seconds=250)
    for i, uri in enumerate(["/index.php?page=../../../../etc/passwd",
                             "/download?file=..%2F..%2Fetc%2Fshadow",
                             "/view.php?f=....//....//windows/win.ini"]):
        rows.append(row(t0 + timedelta(seconds=i * 2), "203.0.113.120", "GET", uri, 400, 0.002))

    # --- diverted traffic (route=honeypot): detector should NOT alert on these again
    t0 = start + timedelta(seconds=270)
    for i in range(10):
        rows.append(row(t0 + timedelta(seconds=i), "203.0.113.99", "GET",
                        rnd.choice(["/.env", "/shell.php?cmd=id", "/admin"]),
                        200, 0.004, route="honeypot"))

    rows.sort(key=lambda r: r["timestamp"])
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sample_deceptiq.jsonl")
    ap.add_argument("--replay", metavar="FILE", help="append lines slowly to FILE")
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between replayed lines")
    args = ap.parse_args()

    rows = build()
    if args.replay:
        with open(args.replay, "a", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
                f.flush()
                time.sleep(args.delay)
        print(f"replayed {len(rows)} lines into {args.replay}")
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        print(f"wrote {len(rows)} lines to {args.out}")


if __name__ == "__main__":
    main()
