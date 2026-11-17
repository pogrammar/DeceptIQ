from __future__ import annotations

import argparse
import csv
import json
import re
import time

from collections import defaultdict, deque
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

DEFAULT_LOG = "samples/nginx_access.jsonl"

DEFAULT_OUTPUT = (
    "data-ingestion/data/anomaly_events.csv"
)

CSV_FIELDS = [
    "event_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "destination_port",
    "anomaly_type",
    "window_seconds",
    "request_count",
    "http_404_count",
    "sensitive_request_count",
    "suspicious_paths",
    "trigger_uri",
    "detector",
]

SENSITIVE_PATHS = (
    "/.env",
    "/.git/",
    "/backup",
    "/config.php",
    "/phpmyadmin",
    "/wp-config.php",
    "/.aws/",
    "/server-status",
    "/actuator/env",
)

TRAVERSAL = re.compile(
    r"(?i)(?:\.\.[/\\]|%2e%2e(?:%2f|/|%5c|\\)|%252e%252e)"
)


# --------------------------------------------------
# 1. TIMESTAMP PARSING
# --------------------------------------------------

def parse_timestamp(value):

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(
            value, timezone.utc
        )

    if not isinstance(value, str):
        raise ValueError(
            "timestamp must be an ISO 8601 string"
        )

    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        raise ValueError(
            "timestamp must include timezone"
        )

    return parsed.astimezone(timezone.utc)


# --------------------------------------------------
# 2. LOG VALIDATION
# --------------------------------------------------

def validate_log(record):

    if not isinstance(record, dict):
        raise ValueError(
            "log entry must be an object"
        )

    required = [
        "timestamp",
        "client_ip",
        "method",
        "uri",
        "status",
    ]

    for field in required:
        if field not in record:
            raise ValueError(
                f"missing field: {field}"
            )

    try:
        ip_address(record["client_ip"])
    except (ValueError, TypeError) as exc:
        raise ValueError(
            "invalid client_ip"
        ) from exc

    try:
        timestamp = parse_timestamp(
            record["timestamp"]
        )
    except (
        ValueError,
        TypeError,
        OverflowError,
    ) as exc:
        raise ValueError(
            "invalid timestamp"
        ) from exc

    method = record["method"]
    uri = record["uri"]
    status = record["status"]

    if (
        not isinstance(method, str)
        or not method
        or len(method) > 20
    ):
        raise ValueError("invalid method")

    if (
        not isinstance(uri, str)
        or not uri.startswith("/")
        or len(uri) > 8192
    ):
        raise ValueError("invalid uri")

    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not 100 <= status <= 599
    ):
        raise ValueError("invalid status")

    # Destination IP is optional for older sample logs.
    destination_ip = record.get("destination_ip")

    if destination_ip is not None:
        try:
            ip_address(destination_ip)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                "invalid destination_ip"
            ) from exc

    # Destination port is optional.
    destination_port = record.get("destination_port")

    if destination_port is not None:
        if (
            isinstance(destination_port, bool)
            or not isinstance(destination_port, int)
            or not 1 <= destination_port <= 65535
        ):
            raise ValueError(
                "invalid destination_port"
            )

    return {
        "timestamp": timestamp,
        "client_ip": record["client_ip"],
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "method": method,
        "uri": uri,
        "status": status,
        "route": record.get("route", "real"),
    }


# --------------------------------------------------
# 3. SUSPICIOUS URI DETECTION
# --------------------------------------------------

def inspect_uri(uri):

    raw_path = urlsplit(uri).path
    decoded = raw_path

    # Decode up to three times to identify
    # common encoded traversal attempts.
    for _ in range(3):

        new = unquote(decoded)

        if new == decoded:
            break

        decoded = new

    lower = decoded.lower()

    sensitive = any(
        lower == path or lower.startswith(path)
        for path in SENSITIVE_PATHS
    )

    traversal = bool(
        TRAVERSAL.search(raw_path)
        or TRAVERSAL.search(decoded)
    )

    return sensitive, traversal, lower


# --------------------------------------------------
# 4. ANOMALY DETECTION ENGINE
# --------------------------------------------------

class AnomalyDetector:

    def __init__(
        self,
        window_seconds=60,
        rate_threshold=100,
        errors_threshold=20,
        sensitive_threshold=3,
        cooldown_seconds=60,
    ):

        self.window_seconds = window_seconds
        self.rate_threshold = rate_threshold
        self.errors_threshold = errors_threshold
        self.sensitive_threshold = sensitive_threshold
        self.cooldown_seconds = cooldown_seconds

        # Separate request windows for each source
        # and destination IP.
        self.windows = defaultdict(deque)

        # Prevent repeated alerts during cooldown.
        self.last_alert = {}

    def process(self, raw):

        item = validate_log(raw)

        # Ignore traffic already routed to honeypot.

        ip = item["client_ip"]
        destination_ip = item["destination_ip"]
        destination_port = item["destination_port"]

        now = item["timestamp"]

        sensitive, traversal, path = inspect_uri(
            item["uri"]
        )

        # Keep traffic for different destinations
        # separate.
        window_key = (
            ip,
            destination_ip,
            destination_port,
        )

        window = self.windows[window_key]

        # Remove old requests outside the window.
        # Logs are assumed to be timestamp-ordered.
        while window and (
            now - window[0][0]
        ).total_seconds() > self.window_seconds:

            window.popleft()

        window.append(
            (
                now,
                item["status"],
                sensitive,
                path,
            )
        )

        request_count = len(window)

        error_count = sum(
            status == 404
            for _, status, _, _ in window
        )

        sensitive_count = sum(
            is_sensitive
            for _, _, is_sensitive, _ in window
        )

        suspicious_paths = sorted({
            path
            for _, _, is_sensitive, path in window
            if is_sensitive
        })

        evidence = {
            "window_seconds": self.window_seconds,
            "request_count": request_count,
            "http_404_count": error_count,
            "sensitive_request_count": sensitive_count,
            "suspicious_paths": suspicious_paths[:30],
        }

        candidates = []

        # Rule 1: High request rate.
        if request_count >= self.rate_threshold:
            candidates.append(
                "HIGH_REQUEST_RATE"
            )

        # Rule 2: Excessive 404 responses.
        if error_count >= self.errors_threshold:
            candidates.append(
                "EXCESSIVE_404_ERRORS"
            )

        # Rule 3: Sensitive endpoint probing.
        if sensitive_count >= self.sensitive_threshold:
            candidates.append(
                "SENSITIVE_PATH_PROBING"
            )

        # Rule 4: Path traversal attempt.
        if traversal:
            candidates.append(
                "PATH_TRAVERSAL_ATTEMPT"
            )

        events = []

        for anomaly_type in candidates:

            alert_key = (
                window_key,
                anomaly_type,
            )

            last = self.last_alert.get(alert_key)

            if last is not None:

                elapsed = (
                    now - last
                ).total_seconds()

                if elapsed < self.cooldown_seconds:
                    continue

            self.last_alert[alert_key] = now

            detail = dict(evidence)

            if anomaly_type == "PATH_TRAVERSAL_ATTEMPT":
                detail["trigger_uri"] = item["uri"]

            event = {
                "event_id": str(uuid4()),
                "timestamp": now.isoformat().replace(
                    "+00:00", "Z"
                ),
                "source_ip": ip,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "anomaly_type": anomaly_type,
                "evidence": detail,
                "detector": "nginx_log_analyzer",
            }

            events.append(event)

        return events


# --------------------------------------------------
# 5. CONVERT ANOMALY EVENT TO CSV ROW
# --------------------------------------------------

def event_to_csv_row(event):

    evidence = event.get("evidence", {})

    return {
        "event_id": event.get("event_id", ""),
        "timestamp": event.get("timestamp", ""),
        "source_ip": event.get("source_ip", ""),
        "destination_ip": event.get(
            "destination_ip", ""
        ),
        "destination_port": event.get(
            "destination_port", ""
        ),
        "anomaly_type": event.get(
            "anomaly_type", ""
        ),
        "window_seconds": evidence.get(
            "window_seconds", ""
        ),
        "request_count": evidence.get(
            "request_count", ""
        ),
        "http_404_count": evidence.get(
            "http_404_count", ""
        ),
        "sensitive_request_count": evidence.get(
            "sensitive_request_count", ""
        ),
        "suspicious_paths": ";".join(
            evidence.get("suspicious_paths", [])
        ),
        "trigger_uri": evidence.get(
            "trigger_uri", ""
        ),
        "detector": event.get("detector", ""),
    }


# --------------------------------------------------
# 6. OPTIONAL HTTP POST TO DECISION ENGINE
# --------------------------------------------------

def post_event(
    event,
    endpoint,
    token=None,
    timeout=3,
    retries=2,
):

    headers = {
        "Content-Type": "application/json"
    }

    if token:
        headers["Authorization"] = (
            f"Bearer {token}"
        )

    payload = json.dumps(event).encode("utf-8")

    for attempt in range(retries + 1):

        try:

            request = Request(
                endpoint,
                data=payload,
                headers=headers,
                method="POST",
            )

            with urlopen(
                request,
                timeout=timeout,
            ) as response:

                if 200 <= response.status < 300:
                    return True

                raise RuntimeError(
                    f"Unexpected response {response.status}"
                )

        except (
            HTTPError,
            URLError,
            TimeoutError,
            RuntimeError,
        ) as exc:

            if attempt == retries:
                print(
                    f"POST failed for "
                    f"{event['event_id']}: {exc}"
                )
                return False

            time.sleep(min(2 ** attempt, 3))

    return False


# --------------------------------------------------
# 7. PROCESS NGINX LOG FILE
# --------------------------------------------------

def process_file(
    log_path,
    output_path,
    detector=None,
    endpoint=None,
    token=None,
):

    detector = detector or AnomalyDetector()

    processed = 0
    invalid = 0
    alerts = 0
    delivered = 0

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        log_path,
        "r",
        encoding="utf-8",
    ) as source, open(
        output_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as sink:

        writer = csv.DictWriter(
            sink,
            fieldnames=CSV_FIELDS,
        )

        writer.writeheader()

        for lineno, line in enumerate(source, 1):

            if not line.strip():
                continue

            try:

                record = json.loads(line)
                events = detector.process(record)

                processed += 1

            except (
                ValueError,
                TypeError,
                json.JSONDecodeError,
            ) as exc:

                invalid += 1

                print(
                    f"Skipping invalid log line "
                    f"{lineno}: {exc}"
                )

                continue

            for event in events:

                writer.writerow(
                    event_to_csv_row(event)
                )

                sink.flush()

                alerts += 1

                print(
                    f"DETECTED {event['anomaly_type']} "
                    f"from {event['source_ip']} "
                    f"to {event['destination_ip']}"
                )

                if endpoint:

                    if post_event(
                        event,
                        endpoint,
                        token=token,
                    ):
                        delivered += 1

    print(
        f"Processed={processed}, "
        f"Invalid={invalid}, "
        f"Alerts={alerts}, "
        f"Delivered={delivered}"
    )

    return {
        "processed": processed,
        "invalid": invalid,
        "alerts": alerts,
        "delivered": delivered,
    }


# --------------------------------------------------
# 8. CONTINUOUS NGINX LOG MONITORING
# --------------------------------------------------

def follow_file(
    log_path,
    output_path,
    detector,
    endpoint=None,
    token=None,
    from_start=False,
):

    log_path = Path(log_path)
    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    file_exists = (
        output_path.exists()
        and output_path.stat().st_size > 0
    )

    with open(
        output_path,
        "a",
        newline="",
        encoding="utf-8",
    ) as sink:

        writer = csv.DictWriter(
            sink,
            fieldnames=CSV_FIELDS,
        )

        if not file_exists:
            writer.writeheader()
            sink.flush()

        source = None
        identity = None

        try:

            while True:

                try:

                    stat = log_path.stat()

                    current_identity = (
                        stat.st_dev,
                        stat.st_ino,
                    )

                    if (
                        source is None
                        or current_identity != identity
                        or stat.st_size < source.tell()
                    ):

                        if source:
                            source.close()

                        source = log_path.open(
                            "r",
                            encoding="utf-8",
                        )

                        identity = current_identity

                        if not from_start:
                            source.seek(0, 2)

                        from_start = True

                    position = source.tell()

                    line = source.readline()

                    if not line:
                        time.sleep(0.25)
                        continue

                    if not line.endswith("\n"):
                        source.seek(position)
                        time.sleep(0.25)
                        continue

                    try:

                        events = detector.process(
                            json.loads(line)
                        )

                    except (
                        ValueError,
                        TypeError,
                        json.JSONDecodeError,
                    ) as exc:

                        print(
                            f"Skipping invalid log entry: {exc}"
                        )

                        continue

                    for event in events:

                        writer.writerow(
                            event_to_csv_row(event)
                        )

                        sink.flush()

                        print(
                            f"DETECTED "
                            f"{event['anomaly_type']} "
                            f"from {event['source_ip']} "
                            f"to {event['destination_ip']}"
                        )

                        if endpoint:
                            post_event(
                                event,
                                endpoint,
                                token=token,
                            )

                except FileNotFoundError:
                    time.sleep(0.5)

        except KeyboardInterrupt:
            print("\nStopping log monitoring.")

        finally:
            if source:
                source.close()


# --------------------------------------------------
# 9. COMMAND-LINE ENTRY POINT
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="DeceptIQ Nginx anomaly detector"
    )

    parser.add_argument(
        "--log",
        default=DEFAULT_LOG,
        help="Input Nginx JSONL log file",
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="Output anomaly CSV file",
    )

    parser.add_argument(
        "--endpoint",
        help="Optional decision engine POST URL",
    )

    parser.add_argument(
        "--token",
        help="Optional API bearer token",
    )

    parser.add_argument(
        "--follow",
        action="store_true",
        help="Monitor newly appended log entries",
    )

    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Read existing log lines when following",
    )

    args = parser.parse_args()

    detector = AnomalyDetector()

    if args.follow:

        follow_file(
            args.log,
            args.output,
            detector,
            args.endpoint,
            args.token,
            args.from_start,
        )

    else:

        process_file(
            args.log,
            args.output,
            detector,
            args.endpoint,
            args.token,
        )


if __name__ == "__main__":
    main()
    