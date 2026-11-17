"""
Simulated attacker for demoing the honeypot.

Only run this against YOUR OWN honeypot (default http://127.0.0.1:8080).
It sends harmless probe requests, the kind automated scanners send, so the
dashboard has realistic data for the presentation.

    python simulate_attacker.py
    python simulate_attacker.py --target http://127.0.0.1:8080 --rounds 2
"""

import argparse
import sys
import time

import requests

PROBES = [
    ("GET", "/", None),
    ("GET", "/robots.txt", None),
    ("GET", "/admin", None),
    ("GET", "/phpmyadmin/", None),
    ("GET", "/wp-login.php", None),
    ("POST", "/wp-login.php", {"username": "admin", "password": "admin123"}),
    ("GET", "/.env", None),
    ("GET", "/.git/config", None),
    ("GET", "/backup.zip", None),
    ("GET", "/shell.php?cmd=whoami", None),
    ("GET", "/index.php?page=../../../../etc/passwd", None),
    ("GET", "/products.php?id=1' OR 1=1 --", None),
    ("GET", "/search.php?q=<script>alert(1)</script>", None),
    ("POST", "/index.php?s=php://input", "<?php system($_GET['c']); ?>"),
    ("GET", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", None),
    ("GET", "/cgi-bin/test.cgi?x=;id", None),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.2)
    args = ap.parse_args()

    if not args.target.startswith(("http://127.0.0.1", "http://localhost")):
        print("Refusing to run against a non-local target.", file=sys.stderr)
        return 2

    ua = {"User-Agent": "sqlmap/1.7 (simulated)"}
    for _ in range(args.rounds):
        for method, path, data in PROBES:
            url = args.target + path
            try:
                r = requests.request(method, url, data=data, headers=ua, timeout=5)
                print(f"{method:5} {path:60} -> {r.status_code}")
            except requests.RequestException as exc:
                print(f"{method:5} {path:60} -> ERROR {exc}")
            time.sleep(args.delay)
    return 0


if __name__ == "__main__":
    sys.exit(main())
