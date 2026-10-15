import json, os, subprocess, sys, urllib.request, urllib.error, hashlib, datetime

OUT = sys.argv[1]
BASE = "http://127.0.0.1:18205"
SOCK = "/tmp/mysp-verify/run/mysql.sock"
PLOG = os.path.join(OUT, "logs", "provider.log")
RLOG = os.path.join(OUT, "logs", "reg.log")
GLOG = "/tmp/mysp-verify/run/mysql-general.log"
cases = []


def size(p):
    return os.path.getsize(p) if os.path.exists(p) else 0


def slice_(p, off):
    with open(p, "rb") as f:
        f.seek(off)
        return f.read().decode("utf-8", "replace")


def sql(q):
    r = subprocess.run(["mysql", "-S", SOCK, "-uroot", "--batch", "--raw", "-e", q, "mplus_ums_admin"],
                       capture_output=True, text=True)
    return r.stdout + r.stderr


def readback(cid, username, targets):
    q = ("SELECT id, username, password, CHAR_LENGTH(password) AS pw_len, CHAR_LENGTH(icon) AS icon_len, "
         "CHAR_LENGTH(email) AS email_len, CHAR_LENGTH(nick_name) AS nick_len, CHAR_LENGTH(note) AS note_len, "
         "create_time, login_time, status FROM ums_admin WHERE username = '%s'" % username.replace("'", "''"))
    res = sql(q)
    path = "raw/%s.json" % cid
    json.dump({"case_id": cid, "query": q, "result": res}, open(os.path.join(OUT, path), "w"), indent=1, ensure_ascii=False)
    cases.append({"case_id": cid, "purpose": "read-back", "target_ids": targets, "endpoint": None,
                  "request_method": None, "request_url": None, "response_status": None, "reached_persistence": None,
                  "evidence": [{"path": path, "kind": "read-back", "description": "SQL read-back of ums_admin row"}],
                  "observation": res.strip() or "(no rows)"})
    return res


def post(cid, purpose, targets, body, note=""):
    po, ro, go = size(PLOG), size(RLOG), size(GLOG)
    data = json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(BASE + "/reg", data=data, method="POST",
                                 headers={"Content-Type": "application/json;charset=UTF-8"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            status, rbody, rh = r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        status, rbody, rh = e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    import time; time.sleep(1.0)
    plog, rlog = slice_(PLOG, po), slice_(RLOG, ro)
    glog = "\n".join(l for l in slice_(GLOG, go).splitlines() if "ums_admin" in l)
    ex = {"case_id": cid, "purpose": purpose, "target_ids": targets, "note": note,
          "request": {"method": "POST", "url": BASE + "/reg", "headers": {"Content-Type": "application/json;charset=UTF-8"}, "body": body},
          "response": {"status": status, "headers": rh, "body": rbody}}
    p1 = "raw/%s.exchange.json" % cid
    json.dump(ex, open(os.path.join(OUT, p1), "w"), indent=1, ensure_ascii=False)
    p2 = "logs/cases/%s.provider.log" % cid
    p3 = "logs/cases/%s.reg.log" % cid
    p4 = "logs/cases/%s.mysql-general.log" % cid
    os.makedirs(os.path.join(OUT, "logs/cases"), exist_ok=True)
    open(os.path.join(OUT, p2), "w").write(plog)
    open(os.path.join(OUT, p3), "w").write(rlog)
    open(os.path.join(OUT, p4), "w").write(glog)
    insert_sent = "INSERT INTO ums_admin" in plog or "INSERT INTO ums_admin" in glog
    sqlerr = [l for l in (plog + rlog).splitlines() if "Data truncation" in l or "Duplicate entry" in l or "SQLIntegrity" in l or "MysqlDataTruncation" in l]
    obs = "HTTP %d; body=%s; insert_statement_reached=%s; sql_errors=%s" % (status, rbody[:400], insert_sent, sqlerr[:2])
    cases.append({"case_id": cid, "purpose": purpose, "target_ids": targets, "endpoint": "POST /reg",
                  "request_method": "POST", "request_url": BASE + "/reg", "response_status": status,
                  "reached_persistence": insert_sent,
                  "evidence": [{"path": p1, "kind": "http-exchange", "description": "full request/response"},
                               {"path": p2, "kind": "application-log", "description": "provider log slice incl. MyBatis SQL debug"},
                               {"path": p3, "kind": "application-log", "description": "reg service log slice"},
                               {"path": p4, "kind": "sql-trace", "description": "MySQL general-log lines touching ums_admin"}],
                  "observation": obs})
    print(cid, obs[:300])
    return status, rbody


U = "pv%s" % datetime.datetime.now().strftime("%H%M%S")
def u(s): return (U + s)[:64]

# ---- controls / boundaries
post("C01-control-valid", "control", ["pc-c82aa238dd70","pc-9b7836344020","pc-06d6fa8e45f7","pc-892ebfa4030e"],
     {"username": u("ok"), "password": "123456", "icon": "http://x/i.png", "email": "a@b.c", "nickName": "nick", "note": "n", "status": 1})
readback("C01-readback", u("ok"), ["pc-c82aa238dd70"])

bu = (U + "b" * 64)[:64]
post("C02-boundary-max-lengths", "boundary",
     ["pc-c82aa238dd70","pc-9b7836344020","pc-d50de559463c","pc-e43967957866","pc-06d6fa8e45f7","pc-892ebfa4030e","pc-07d96eea81e8","pc-5963beda89f5","pc-2b498cc952d3","pc-fac4a3c36dd7"],
     {"username": bu, "password": "p", "icon": "i" * 500, "email": "e" * 100, "nickName": "k" * 200, "note": "o" * 500})
readback("C02-readback", bu, ["pc-c82aa238dd70","pc-d50de559463c","pc-06d6fa8e45f7","pc-07d96eea81e8","pc-2b498cc952d3"])

# ---- violations: lengths / varchar types
lu = (U + "L" * 65)[:65]
post("V01-username-65", "violation", ["pc-c82aa238dd70","pc-9b7836344020"], {"username": lu, "password": "123456"})
readback("V01-readback", lu, ["pc-c82aa238dd70","pc-9b7836344020"])

post("V02-icon-501", "violation", ["pc-d50de559463c","pc-e43967957866"], {"username": u("icon"), "password": "123456", "icon": "i" * 501})
readback("V02-readback", u("icon"), ["pc-d50de559463c","pc-e43967957866"])

post("V03-email-101", "violation", ["pc-06d6fa8e45f7","pc-892ebfa4030e"], {"username": u("email"), "password": "123456", "email": "e" * 101})
readback("V03-readback", u("email"), ["pc-06d6fa8e45f7","pc-892ebfa4030e"])

post("V04-nickname-201", "violation", ["pc-07d96eea81e8","pc-5963beda89f5"], {"username": u("nick"), "password": "123456", "nickName": "k" * 201})
readback("V04-readback", u("nick"), ["pc-07d96eea81e8","pc-5963beda89f5"])

post("V05-note-501", "violation", ["pc-2b498cc952d3","pc-fac4a3c36dd7"], {"username": u("note"), "password": "123456", "note": "o" * 501})
readback("V05-readback", u("note"), ["pc-2b498cc952d3","pc-fac4a3c36dd7"])

post("V06-password-100", "violation", ["pc-c94103dbb013","pc-4025353f3429"], {"username": u("pw"), "password": "P" * 100})
readback("V06-readback", u("pw"), ["pc-c94103dbb013","pc-4025353f3429"])

# ---- id: PK, not-null, BIGINT
post("V07-id-duplicate-pk", "violation", ["pc-830c39ccfb6b"], {"id": 1, "username": u("dup"), "password": "123456"})
readback("V07-readback", u("dup"), ["pc-830c39ccfb6b"])
post("V08-id-null", "violation", ["pc-566dafe4ec19"], {"id": None, "username": u("nullid"), "password": "123456"})
readback("V08-readback", u("nullid"), ["pc-566dafe4ec19"])
post("V09-id-over-bigint", "violation", ["pc-4077068a2bf5"], {"id": 9223372036854775808, "username": u("bigid"), "password": "123456"})
readback("V09-readback", u("bigid"), ["pc-4077068a2bf5"])
post("V10-id-non-integer", "violation", ["pc-4077068a2bf5"], {"id": "abc", "username": u("strid"), "password": "123456"})
post("C03-id-bigint-max", "boundary", ["pc-4077068a2bf5"], {"id": 9223372036854775000, "username": u("maxid"), "password": "123456"})
readback("C03-readback", u("maxid"), ["pc-4077068a2bf5"])

# ---- status INT(1)
post("V11-status-over-int", "violation", ["pc-bcab32ac6f64"], {"username": u("st"), "password": "123456", "status": 2147483648})
readback("V11-readback", u("st"), ["pc-bcab32ac6f64"])
post("V12-status-non-integer", "violation", ["pc-bcab32ac6f64"], {"username": u("st2"), "password": "123456", "status": "x"})
post("C04-status-int-max-display-width", "boundary", ["pc-bcab32ac6f64"], {"username": u("st3"), "password": "123456", "status": 2147483647})
readback("C04-readback", u("st3"), ["pc-bcab32ac6f64"])

# ---- DATETIME
post("V13-createtime-loginTime-out-of-range", "violation", ["pc-4b80a8cb1221","pc-f2ed0251561b"],
     {"username": u("dt"), "password": "123456", "createTime": "10000-01-01 00:00:00", "loginTime": "10000-01-01 00:00:00"})
readback("V13-readback", u("dt"), ["pc-4b80a8cb1221","pc-f2ed0251561b"])
post("V14-createtime-garbage", "violation", ["pc-4b80a8cb1221","pc-f2ed0251561b"],
     {"username": u("dt2"), "password": "123456", "createTime": "not-a-date", "loginTime": "not-a-date"})
readback("V14-readback", u("dt2"), ["pc-4b80a8cb1221","pc-f2ed0251561b"])

json.dump(cases, open(os.path.join(OUT, "raw", "cases.json"), "w"), indent=1, ensure_ascii=False)
