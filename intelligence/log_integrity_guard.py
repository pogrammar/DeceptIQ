#!/usr/bin/env python3


import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import sys
import time
from datetime import datetime

ZERO = '0' * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def atomic_json(path, value):
    tmp = path.with_name(path.name + '.tmp')
    with tmp.open('w', encoding='utf-8', newline='\n') as f:
        json.dump(value, f, separators=(',', ':'))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def validate(item):
    if not isinstance(item, dict):
        raise ValueError('record is not an object')
    for field in ('timestamp', 'client_ip', 'destination_ip', 'method', 'uri', 'route'):
        if not isinstance(item.get(field), str):
            raise ValueError('missing/invalid ' + field)
    dt = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp lacks timezone')
    ipaddress.ip_address(item['client_ip'])
    ipaddress.ip_address(item['destination_ip'])
    if type(item.get('destination_port')) is not int or not 1 <= item['destination_port'] <= 65535:
        raise ValueError('invalid destination_port')
    if type(item.get('status')) is not int or not 100 <= item['status'] <= 599:
        raise ValueError('invalid status')
    if item['route'] not in ('real', 'honeypot'):
        raise ValueError('invalid route')
    return item


def digest(key, seq, previous, event):
    data = canonical({'seq': seq, 'prev': previous, 'event': event})
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def audit(journal, checkpoint, key):
    # The checkpoint is authoritative and MUST be protected separately from the journal.
    expected = json.loads(checkpoint.read_text(encoding='utf-8')) if checkpoint.exists() else {'seq': 0, 'mac': ZERO}
    seq, previous = 0, ZERO
    if journal.exists():
        with journal.open('r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                try:
                    row = json.loads(line)
                    if row['seq'] != seq + 1 or row['prev'] != previous:
                        raise ValueError('broken sequence/previous MAC')
                    validate(row['event'])
                    calculated = digest(key, row['seq'], row['prev'], row['event'])
                    if not hmac.compare_digest(calculated, row['mac']):
                        raise ValueError('HMAC mismatch')
                    seq, previous = row['seq'], row['mac']
                except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
                    raise RuntimeError(f'INTEGRITY VIOLATION at journal line {line_no}: {e}') from e
    if expected != {'seq': seq, 'mac': previous}:
        raise RuntimeError('INTEGRITY VIOLATION: journal does not match protected checkpoint (deletion/truncation or incomplete write)')
    return seq, previous


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True)
    p.add_argument('--journal', required=True)
    p.add_argument('--verified', required=True)
    p.add_argument('--checkpoint', required=True)
    p.add_argument('--key-file', required=True)
    p.add_argument('--audit-only', action='store_true')
    p.add_argument('--from-start', action='store_true', help='ONLY on first setup; otherwise start at EOF')
    args = p.parse_args()
    source, journal, verified, checkpoint, key_file = map(Path, (args.source, args.journal, args.verified, args.checkpoint, args.key_file))
    if not key_file.exists():
        raise SystemExit('Missing key file. Generate a random 32-byte key using setup command.')
    key = key_file.read_bytes()
    if len(key) < 32:
        raise SystemExit('Key must be at least 32 random bytes')
    seq, previous = audit(journal, checkpoint, key)
    print(f'Journal integrity OK: {seq} records', flush=True)
    if args.audit_only:
        return
    if not source.exists():
        raise SystemExit(f'Nginx log does not exist: {source}')
    if not journal.exists() and checkpoint.exists():
        raise SystemExit('Checkpoint exists but journal missing')
    # Do not silently resume with an unknown source offset. On restart start at
    # current EOF; requests during downtime are not attested. Fail-safe disclosure.
    if seq:
        print('WARNING: Restart resumes at current source EOF; records while guard was offline are NOT attested.', flush=True)
    with source.open('r', encoding='utf-8', errors='strict') as input_file:
        if not args.from_start or seq:
            input_file.seek(0, os.SEEK_END)
        print('Watching Nginx log. Only newly captured entries are signed.', flush=True)
        last_audit = time.monotonic()
        while True:
            if time.monotonic() - last_audit >= 2:
                audit(journal, checkpoint, key)
                last_audit = time.monotonic()
            pos = input_file.tell()
            line = input_file.readline()
            if not line:
                time.sleep(.05)
                continue
            if not line.endswith('\n'):
                input_file.seek(pos)
                time.sleep(.05)
                continue
            try:
                event = validate(json.loads(line))
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
                print(f'REJECTED malformed source log: {e}', file=sys.stderr, flush=True)
                continue
            new_seq = seq + 1
            mac = digest(key, new_seq, previous, event)
            record = {'seq': new_seq, 'prev': previous, 'event': event, 'mac': mac}
            # Journal first; if interrupted before checkpoint update, fail closed
            # on restart instead of silently accepting a partial state.
            journal.parent.mkdir(parents=True, exist_ok=True)
            with journal.open('a', encoding='utf-8', newline='\n') as out:
                out.write(canonical(record).decode('utf-8') + '\n')
                out.flush()
                os.fsync(out.fileno())
            atomic_json(checkpoint, {'seq': new_seq, 'mac': mac})
            seq, previous = new_seq, mac
            # This file is an output of the trusted guard, not a signed artifact.
            # Protect its ACL so the detector cannot be fed injected lines.
            with verified.open('a', encoding='utf-8', newline='\n') as out:
                out.write(canonical(event).decode('utf-8') + '\n')
                out.flush()
            print(f'VERIFIED seq={seq} ip={event["client_ip"]} uri={event["uri"]}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError) as exc:
        print(f'STOPPED: {exc}', file=sys.stderr, flush=True)
        sys.exit(2)
