#!/usr/bin/env python3
"""Verification harness for spinnaker_kayenta SQL storage. Records each HTTP exchange, the
correlated application-log slice and a MySQL read-back for every case."""
import json, os, subprocess, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:18204"
OUT = "/artifact/results/RQ1/spinnaker_kayenta/spinnaker_kayenta-20260929T162038Z-8d598796/output"
APPLOG = os.path.join(OUT, "logs", "kayenta-app.log")
SOCK = "/tmp/kayenta-verif-8d598796/mysql/run/mysqld.sock"
summary = {}


def sql(q):
    r = subprocess.run(["mysql", "-S", SOCK, "-uroot", "kayenta", "--batch", "-e", q],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def http(method, path, body=None, raw_body=None):
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def case(cid, purpose, targets, method, path, body=None, raw_body=None, readback=None):
    start = os.path.getsize(APPLOG)
    t0 = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    status, resp = http(method, path, body, raw_body)
    time.sleep(0.7)
    with open(APPLOG, errors="replace") as f:
        f.seek(start)
        logslice = f.read()
    rb = sql(readback) if readback else None
    rec = {"case_id": cid, "purpose": purpose, "target_ids": targets, "timestamp": t0,
           "request": {"method": method, "url": BASE + path,
                       "headers": {"Content-Type": "application/json"} if (body is not None or raw_body is not None) else {},
                       "body": body if raw_body is None else raw_body.decode(errors="replace")},
           "response": {"status": status, "body": resp},
           "readback_sql": readback, "readback_result": rb}
    with open(os.path.join(OUT, "raw", cid + ".json"), "w") as f:
        json.dump(rec, f, indent=2)
    with open(os.path.join(OUT, "logs", "cases", cid + ".log"), "w") as f:
        f.write(logslice)
    summary[cid] = {"status": status, "resp": resp[:400], "readback": rb,
                    "log_errors": [l[:300] for l in logslice.splitlines()
                                   if any(k in l for k in ("ERROR", "WARN", "SQL Error", "Data too long", "Duplicate"))][:8],
                    "log_sql": [l[l.find("DEBUG"):][:200] for l in logslice.splitlines() if "org.hibernate.SQL" in l][:8]}
    print(cid, status, resp[:200].replace("\n", " "))
    return status, resp


os.makedirs(os.path.join(OUT, "logs", "cases"), exist_ok=True)


def cfg(cid=None, name="cfgvalid"):
    b = {"name": name, "applications": ["verifapp"], "metrics": [], "classifier": {"groupWeights": {}},
         "judge": {"name": "NetflixACAJudge-v1.0", "judgeConfigurations": {}}, "configVersion": "1"}
    if cid is not None:
        b["id"] = cid
    return b


A = "configurationAccountName=sql-account"
CC = "SELECT id, CHAR_LENGTH(id) AS id_len, JSON_VALID(content) AS json_valid, JSON_TYPE(content) AS json_type, created_at, updated_at FROM canary_config WHERE id {w}"
ID255 = "cc-" + "a" * 252
ID256 = "cc-" + "b" * 253

# ---- canary_config ----
case("CC-01-control-create", "control", ["pc-11859c35fe9a", "pc-697814377ac0", "pc-28c967fd981a", "pc-cd98250264a6", "pc-e3c4f3bbce3b", "pc-03dd49ea23ba", "pc-454b6220f809"],
     "POST", "/canaryConfig?" + A, cfg("cc-valid-001"), readback=CC.format(w="='cc-valid-001'"))
case("CC-02-readback-api", "read-back", ["pc-28c967fd981a"], "GET", "/canaryConfig/cc-valid-001?" + A,
     readback="SELECT COUNT(*) AS n FROM canary_config")
case("CC-03-boundary-id-255", "boundary", ["pc-900bdfd125e0", "pc-d4dc77dfb22b"], "POST", "/canaryConfig?" + A, cfg(ID255),
     readback=CC.format(w="LIKE 'cc-aaaa%'"))
case("CC-04-violation-id-256", "violation", ["pc-900bdfd125e0", "pc-d4dc77dfb22b"], "POST", "/canaryConfig?" + A, cfg(ID256),
     readback="SELECT COUNT(*) AS n_rows_like_256 FROM canary_config WHERE id LIKE 'cc-bbbb%'")
case("CC-05-violation-duplicate-id", "violation", ["pc-82610b8aefc0", "pc-5a7d64fe7c3a"], "POST", "/canaryConfig?" + A, cfg("cc-valid-001", "cfgdup"),
     readback="SELECT id, JSON_UNQUOTE(JSON_EXTRACT(content,'$.name')) AS name FROM canary_config WHERE id='cc-valid-001'")
case("CC-06-boundary-duplicate-id-case-variant", "boundary", ["pc-82610b8aefc0", "pc-5a7d64fe7c3a"], "POST", "/canaryConfig?" + A, cfg("CC-VALID-001", "cfgcase"),
     readback="SELECT id, JSON_UNQUOTE(JSON_EXTRACT(content,'$.name')) AS name FROM canary_config WHERE id='cc-valid-001'")
case("CC-07-update-same-id", "boundary", ["pc-82610b8aefc0", "pc-5a7d64fe7c3a"], "PUT", "/canaryConfig/cc-valid-001?" + A, cfg(None, "cfgupdated"),
     readback="SELECT id, JSON_UNQUOTE(JSON_EXTRACT(content,'$.name')) AS name, created_at, updated_at, (SELECT COUNT(*) FROM canary_config WHERE id='cc-valid-001') AS n FROM canary_config WHERE id='cc-valid-001'")
case("CC-08-violation-null-id", "violation", ["pc-03e7ed0064f7"], "POST", "/canaryConfig?" + A, cfg(None, "cfgnullid"),
     readback="SELECT id, CHAR_LENGTH(id) AS id_len, JSON_UNQUOTE(JSON_EXTRACT(content,'$.id')) AS content_id FROM canary_config WHERE JSON_UNQUOTE(JSON_EXTRACT(content,'$.name'))='cfgnullid'")
case("CC-09-violation-empty-id", "violation", ["pc-03e7ed0064f7"], "POST", "/canaryConfig?" + A, cfg("", "cfgemptyid"),
     readback="SELECT id, CHAR_LENGTH(id) AS id_len FROM canary_config WHERE JSON_UNQUOTE(JSON_EXTRACT(content,'$.name'))='cfgemptyid'")
case("CC-10-violation-null-content", "violation", ["pc-697814377ac0"], "POST", "/canaryConfig?" + A, raw_body=b"null",
     readback="SELECT COUNT(*) AS n FROM canary_config")

# ---- canary_archive ----
R = "storageAccountName=sql-account"
CA = "SELECT id, CHAR_LENGTH(id) AS id_len, JSON_VALID(content) AS json_valid, JSON_TYPE(content) AS json_type, created_at, updated_at FROM canary_archive WHERE id {w}"
arch = {"application": "verifapp", "pipelineId": "p", "stageStatus": {"s1": "succeeded"}, "complete": True, "status": "succeeded"}
AID255 = "ca-" + "a" * 252
AID256 = "ca-" + "b" * 253
case("CA-01-control-create", "control", ["pc-11859c35fe9a", "pc-b223c202dd17", "pc-fdc864d03407", "pc-343b4ffdfac5", "pc-990df09fb055", "pc-89d1cd05bf3c", "pc-89db031a1827"],
     "POST", "/canaryResultArchive?" + R + "&pipelineId=ca-valid-001", arch, readback=CA.format(w="='ca-valid-001'"))
case("CA-02-readback-api", "read-back", ["pc-fdc864d03407"], "GET", "/canaryResultArchive/ca-valid-001?" + R)
case("CA-03-boundary-id-255", "boundary", ["pc-cf94e5cb7efc", "pc-11859c35fe9a"], "POST", "/canaryResultArchive?" + R + "&pipelineId=" + AID255, arch,
     readback=CA.format(w="LIKE 'ca-aaaa%'"))
case("CA-04-violation-id-256", "violation", ["pc-cf94e5cb7efc", "pc-11859c35fe9a"], "POST", "/canaryResultArchive?" + R + "&pipelineId=" + AID256, arch,
     readback="SELECT COUNT(*) AS n_rows_like_256 FROM canary_archive WHERE id LIKE 'ca-bbbb%'")
case("CA-05-violation-duplicate-id", "violation", ["pc-000a33b9c80b"], "POST", "/canaryResultArchive?" + R + "&pipelineId=ca-valid-001", dict(arch, application="dupapp"),
     readback="SELECT id, JSON_UNQUOTE(JSON_EXTRACT(content,'$.application')) AS application FROM canary_archive WHERE id='ca-valid-001'")
case("CA-06-update-same-id", "boundary", ["pc-000a33b9c80b"], "PUT", "/canaryResultArchive/ca-valid-001?" + R, dict(arch, application="updatedapp"),
     readback="SELECT id, JSON_UNQUOTE(JSON_EXTRACT(content,'$.application')) AS application, (SELECT COUNT(*) FROM canary_archive WHERE id='ca-valid-001') AS n FROM canary_archive WHERE id='ca-valid-001'")
case("CA-07-violation-null-id", "violation", ["pc-3c41052834d2"], "POST", "/canaryResultArchive?" + R, dict(arch, application="nullidapp"),
     readback="SELECT id, CHAR_LENGTH(id) AS id_len FROM canary_archive WHERE JSON_UNQUOTE(JSON_EXTRACT(content,'$.application'))='nullidapp'")
case("CA-08-violation-null-content", "violation", ["pc-b223c202dd17"], "POST", "/canaryResultArchive?" + R + "&pipelineId=ca-null-content", raw_body=b"null",
     readback="SELECT COUNT(*) AS n FROM canary_archive WHERE id='ca-null-content'")

# ---- metric_sets ----
ms = [{"name": "cpu", "tags": {"a": "b"}, "startTimeMillis": 0, "startTimeIso": "1970-01-01T00:00:00Z",
       "endTimeMillis": 60000, "endTimeIso": "1970-01-01T00:01:00Z", "stepMillis": 60000, "values": [1.0, 2.0]}]
M = "accountName=sql-account"
case("MS-01-control-create", "control", ["pc-34efbcce606b", "pc-b2886370da3b", "pc-2b8c47e5d7bd", "pc-2611c9ac3275", "pc-4ff0c7f191dd", "pc-0a2ac553dd29", "pc-aadee8576d99", "pc-4ee8f253c4e1", "pc-bcfeaadde2a6", "pc-f2aa380a79e9"],
     "POST", "/metricSetList?" + M, ms,
     readback="SELECT id, CHAR_LENGTH(id) AS id_len, JSON_VALID(content) AS json_valid, JSON_TYPE(content) AS json_type, created_at, updated_at FROM metric_sets")
case("MS-02-violation-null-content", "violation", ["pc-2b8c47e5d7bd"], "POST", "/metricSetList?" + M, raw_body=b"null",
     readback="SELECT COUNT(*) AS n FROM metric_sets")

# ---- metric_set_pairs ----
msp = [{"name": "cpu", "id": "pair-1", "tags": {"a": "b"}, "values": {"control": [1.0], "experiment": [2.0]},
        "scopes": {"control": {"startTimeMillis": 0, "startTimeIso": "1970-01-01T00:00:00Z", "stepMillis": 60000},
                   "experiment": {"startTimeMillis": 0, "startTimeIso": "1970-01-01T00:00:00Z", "stepMillis": 60000}}}]
case("MSP-01-control-create", "control", ["pc-88c6ef457170", "pc-a56ff232d178", "pc-c69dfeadd911", "pc-ab279b731a74", "pc-914538813632", "pc-216b2a3dbc5e", "pc-893aeb4d6f06", "pc-6e7266c1819b", "pc-25e267f034f9", "pc-5f7f9ca6c44d"],
     "POST", "/metricSetPairList?" + M, msp,
     readback="SELECT id, CHAR_LENGTH(id) AS id_len, JSON_VALID(content) AS json_valid, JSON_TYPE(content) AS json_type, created_at, updated_at FROM metric_set_pairs")
case("MSP-02-violation-null-content", "violation", ["pc-c69dfeadd911"], "POST", "/metricSetPairList?" + M, raw_body=b"null",
     readback="SELECT COUNT(*) AS n FROM metric_set_pairs")

with open(os.path.join(OUT, "raw", "_case-summary.json"), "w") as f:
    json.dump(summary, f, indent=2)
