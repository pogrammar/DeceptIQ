"""
Generate TEST TRAFFIC through your Nginx so it writes real lines to deceptiq.jsonl.

Local use only (your own machine). Default target is Nginx on port 8080.

  python gen_traffic.py                    # all phases
  python gen_traffic.py normal             # just normal browsing
  python gen_traffic.py scanner            # 404s + sensitive paths + traversal
  python gen_traffic.py spike              # burst of requests
  python gen_traffic.py --target http://127.0.0.1:8080

Note: every request comes from YOUR machine, so they all show the same client_ip
(127.0.0.1). That's fine for testing the rules. Nginx overwrites X-Forwarded-For
on purpose, so you can't fake other IPs through it.
"""
import argparse
import sys
import time

import requests

NORMAL = ["/", "/about", "/products", "/products/42", "/contact", "/static/app.css"]
SENSITIVE = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/",
             "/backup.zip", "/admin", "/config.php"]
TRAVERSAL = ["/index.php?page=../../../../etc/passwd",
             "/download?file=..%2F..%2Fetc%2Fshadow",
             "/view.php?f=....//....//windows/win.ini"]


def hit(s, base, path, delay):
    try:
        r = s.get(base + path, timeout=5)
        print(f"{r.status_code}  {path}")
    except requests.RequestException as exc:
        print(f"ERR  {path}  ({exc})")
    time.sleep(delay)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", nargs="?", default="all",
                    choices=["all", "normal", "scanner", "spike"])
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()
    if not args.target.startswith(("http://127.0.0.1", "http://localhost")):
        print("Local targets only.", file=sys.stderr)
        return 2

    s = requests.Session()
    if args.phase in ("all", "normal"):
        print("--- normal browsing")
        for p in NORMAL * 2:
            hit(s, args.target, p, 0.3)
    if args.phase in ("all", "scanner"):
        print("--- scanner: 404 burst")
        for i in range(25):
            hit(s, args.target, f"/page{i}.php", 0.05)
        print("--- scanner: sensitive paths")
        for p in SENSITIVE:
            hit(s, args.target, p, 0.2)
        print("--- scanner: path traversal")
        for p in TRAVERSAL:
            hit(s, args.target, p, 0.2)
    if args.phase in ("all", "spike"):
        print("--- request spike (100 requests, no delay)")
        for _ in range(100):
            hit(s, args.target, "/products", 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
