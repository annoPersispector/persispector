import json, os, re, sys, time, urllib.request, urllib.parse, http.cookiejar

OUT = os.path.dirname(os.path.abspath(__file__))
BASE = "http://127.0.0.1:18207"
LOG = os.path.join(OUT, "logs", "app.log")
CARD = "3a3e99f0-5ad9-47fa-961d-d75fab32ef0e"


def http(method, path, body=None, headers=None):
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, dict(r.headers), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def case(cid, method, path, body=None):
    off = os.path.getsize(LOG)
    hdrs = {"Content-Type": "application/json"} if body is not None else {}
    st, rh, rb = http(method, path, body, hdrs)
    time.sleep(0.4)
    with open(LOG, "rb") as f:
        f.seek(off)
        logslice = f.read().decode(errors="replace")
    with open(os.path.join(OUT, "logs", cid + ".log"), "w") as f:
        f.write(logslice)
    rec = {"case_id": cid, "request": {"method": method, "url": BASE + path, "headers": hdrs, "body": body},
           "response": {"status": st, "headers": rh, "body": rb}}
    with open(os.path.join(OUT, "raw", cid + ".json"), "w") as f:
        json.dump(rec, f, indent=1)
    print(f"--- {cid}: {method} {path} {body} -> {st} {rb[:300]}")
    for l in logslice.splitlines():
        if re.search(r"insert|update|binding parameter|Exception|ERROR|WARN|Caused", l, re.I):
            print("   LOG:", l[:260])
    return st, rb


def h2query(cid, sql):
    cj = http_cookie = http.cookiejar.CookieJar() if False else None
    opener = urllib.request.build_opener()
    r = opener.open(BASE + "/h2-console/", timeout=20).read().decode()
    js = re.search(r"jsessionid=([0-9a-f]+)", r).group(1)
    form = urllib.parse.urlencode({"language": "en", "setting": "Generic H2 (Embedded)", "name": "Generic H2 (Embedded)",
                                   "driver": "org.h2.Driver", "url": "jdbc:h2:mem:testdb", "user": "sa", "password": ""}).encode()
    opener.open(BASE + "/h2-console/login.do?jsessionid=" + js, data=form, timeout=20).read()
    res = opener.open(BASE + "/h2-console/query.do?jsessionid=" + js,
                      data=urllib.parse.urlencode({"sql": sql}).encode(), timeout=20).read().decode()
    rows = re.findall(r"<tr>(.*?)</tr>", res, re.S)
    table = [[re.sub(r"<.*?>", "", c).strip() for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S)] for row in rows]
    with open(os.path.join(OUT, "raw", cid + ".json"), "w") as f:
        json.dump({"case_id": cid, "channel": "H2 web console (same JVM, port 18207) read-back",
                   "sql": sql, "parsed_rows": table, "response_html": res}, f, indent=1)
    print(f"--- {cid}: {sql}")
    for t in table:
        print("   ", t)
    return table


if __name__ == "__main__":
    exec(sys.stdin.read())
