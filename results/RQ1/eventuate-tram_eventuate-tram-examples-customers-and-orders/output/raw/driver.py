#!/usr/bin/env python3
"""Verification driver: sends HTTP cases to order-service on 127.0.0.1:18202 and records
request/response, correlated application-log slice and MySQL read-back per case."""
import json, os, subprocess, sys, time, urllib.request, urllib.error

OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'output'))
LOG = os.path.join(OUT, 'logs', 'order-service.log')
BASE = 'http://127.0.0.1:18202'
SOCK = '/tmp/pv18202/mysql.sock'


def sql(q):
    r = subprocess.run(['mysql', '-uroot', '-S', SOCK, '--batch', 'eventuate', '-e', q],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def http(method, path, body=None):
    data = None if body is None else (body if isinstance(body, str) else json.dumps(body)).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def snapshot():
    return {
        'orders_count': sql('SELECT COUNT(*) AS n FROM orders'),
        'message_count': sql('SELECT COUNT(*) AS n FROM message'),
    }


def run(case_id, purpose, method, path, body, readback_sql=()):
    before = snapshot()
    off = os.path.getsize(LOG)
    body_text = body if isinstance(body, str) or body is None else json.dumps(body)
    status, headers, resp = http(method, path, body)
    time.sleep(1.0)
    with open(LOG, 'rb') as f:
        f.seek(off)
        log_slice = f.read().decode(errors='replace')
    after = snapshot()
    rb = {q: sql(q) for q in readback_sql}
    rec = {
        'case_id': case_id, 'purpose': purpose,
        'request': {'method': method, 'url': BASE + path, 'headers': {'Content-Type': 'application/json'},
                    'body': body_text, 'body_length': None if body_text is None else len(body_text)},
        'response': {'status': status, 'headers': headers, 'body': resp},
        'db_before': before, 'db_after': after, 'readback': rb,
    }
    with open(os.path.join(OUT, 'raw', f'{case_id}.json'), 'w') as f:
        json.dump(rec, f, indent=2)
    with open(os.path.join(OUT, 'logs', f'{case_id}.log'), 'w') as f:
        f.write(log_slice)
    print(case_id, status, resp[:200], before, after)
    return rec


if __name__ == '__main__':
    exec(open(sys.argv[1]).read())
