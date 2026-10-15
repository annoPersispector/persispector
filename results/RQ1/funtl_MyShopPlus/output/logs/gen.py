import json, hashlib, os, datetime, subprocess
ROOT = "/artifact/results/RQ1/funtl_MyShopPlus/funtl_MyShopPlus-20260929T160737Z-ae489bc7"
OUT = ROOT + "/output"
d = json.load(open(ROOT + "/inputs/persistence-constraints.json"))
F = {x["finding_id"]: x for x in d["findings"]}
cases = json.load(open(OUT + "/raw/cases.json"))
C = {c["case_id"]: c for c in cases}


def sha(p):
    return hashlib.sha256(open(os.path.join(OUT, p), "rb").read()).hexdigest()


def ev(p, kind, desc):
    return {"path": p, "kind": kind, "description": desc, "sha256": sha(p)}


def case_ev(ids):
    out = []
    for i in ids:
        for e in C[i]["evidence"]:
            out.append(dict(e, sha256=sha(e["path"])))
    return out


for c in cases:
    for e in c["evidence"]:
        e["sha256"] = sha(e["path"])

INV = ev("raw/table-reference-inventory.txt", "source", "Inventory of all table/mapper/token-store references in the application sources")
PATCH = ev("patches/deployment-compat.txt", "patch", "Compatibility-only deployment adjustments (no source changes)")
COMMON_LIM = ["Runtime DB is MySQL 8.0.42 with default strict sql_mode (STRICT_TRANS_TABLES). The original deployment targets TiDB at tidb.funtl.com:4000, which was not available; enforcement under TiDB or a non-strict MySQL sql_mode may differ.",
              "Only the POST /reg insert path (business-reg -> Dubbo -> provider-admin-service) was deployed. The profile update paths (POST /profile/update, /profile/modify/icon, /profile/modify/password) write the same table, but they need the OAuth2 resource server (business-oauth2 + Redis + extra HTTP port) and were not exercised."]

R = {}


def res(tid, outcome, exact, obs, app, handling, cids, rationale, conf, lim=None, extra_ev=None):
    R[tid] = {"target_id": tid, "target_kind": "constraint", "outcome": outcome, "exact_predicate_confirmed": exact,
              "observed_enforcement": obs, "application_layer_implemented": app, "response_handling": handling,
              "case_ids": cids, "evidence": case_ev(cids) + (extra_ev or []), "rationale": rationale,
              "confidence": conf, "limitations": (lim or []) + COMMON_LIM}


def dbrej(tids, col, n, vcase, rcase, bcases):
    for tid in tids:
        p = F[tid]["predicate"]
        res(tid, "DATABASE_ENFORCED_UNHANDLED", True, "database", False, "unhandled", bcases + [vcase, rcase],
            f"Predicate '{p}'. {vcase}: POST /reg with {col} of {n+1} characters passed RegController.validateReg (it only checks for a duplicate username) "
            f"and UmsAdminServiceImpl.insert. The MyBatis INSERT INTO ums_admin reached MySQL (provider SQL debug log + MySQL general log) and was rejected with "
            f"MysqlDataTruncation 'Data too long for column {col}'. The DataIntegrityViolationException went back over Dubbo, and the client got a generic HTTP 500 "
            f"Spring error body exposing the raw SQL exception. Read-back {rcase} shows no row was persisted. Boundary case C02 ({n} characters) was accepted and read back at exactly {n} characters, "
            f"which matches the extracted limit exactly. No application-layer length validation exists.", 0.95)


dbrej(["pc-c82aa238dd70", "pc-9b7836344020"], "username", 64, "V01-username-65", "V01-readback", ["C01-control-valid", "C02-boundary-max-lengths", "C02-readback"])
dbrej(["pc-d50de559463c", "pc-e43967957866"], "icon", 500, "V02-icon-501", "V02-readback", ["C02-boundary-max-lengths", "C02-readback"])
dbrej(["pc-06d6fa8e45f7", "pc-892ebfa4030e"], "email", 100, "V03-email-101", "V03-readback", ["C02-boundary-max-lengths", "C02-readback"])
dbrej(["pc-07d96eea81e8", "pc-5963beda89f5"], "nick_name", 200, "V04-nickname-201", "V04-readback", ["C02-boundary-max-lengths", "C02-readback"])
dbrej(["pc-2b498cc952d3", "pc-fac4a3c36dd7"], "note", 500, "V05-note-501", "V05-readback", ["C02-boundary-max-lengths", "C02-readback"])

for tid in ["pc-c94103dbb013", "pc-4025353f3429"]:
    res(tid, "APPLICATION_TRANSFORMED", True, "application", True, "elegant", ["V06-password-100", "V06-readback", "C01-readback"],
        f"Predicate '{F[tid]['predicate']}'. V06: POST /reg with a 100-character password returned HTTP 200. UmsAdminServiceImpl.initUmsAdmin replaces the raw password with "
        "BCryptPasswordEncoder.encode(password) before the INSERT. The SQL trace shows a 60-character $2a$10$ hash was bound, and read-back V06-readback shows CHAR_LENGTH(password)=60. "
        "Any client-supplied length is transformed into a fixed 60-character value, so the application layer structurally satisfies VARCHAR(64).", 0.9,
        ["BCrypt truncates input past 72 bytes. That is a separate semantic effect and not a persistence predicate."])

res("pc-830c39ccfb6b", "DATABASE_ENFORCED_UNHANDLED", True, "database", False, "unhandled", ["C01-control-valid", "V07-id-duplicate-pk", "V07-readback"],
    "Predicate 'Columns id identify a row' (PRIMARY KEY ums_admin.id). The request body binds straight to UmsAdmin, so the client controls id. V07: POST /reg with id=1 (seeded user 'test') and a new username. "
    "The provider executed INSERT ... VALUES(1, ...), and MySQL raised SQLIntegrityConstraintViolationException \"Duplicate entry '1' for key 'ums_admin.PRIMARY'\" "
    "(Spring DuplicateKeyException). The client got a generic HTTP 500 with the raw exception text. Read-back shows no row for the new username. The application does not check for duplicate ids.", 0.95)

res("pc-566dafe4ec19", "STRUCTURAL_NOT_RUNTIME_PREDICATE", False, "not-applicable", False, "not-applicable", ["V08-id-null", "V08-readback"],
    "Predicate 'ums_admin.id must not be null'. ums_admin.id is BIGINT NOT NULL AUTO_INCREMENT. V08 sent id=null. The provider executed INSERT ... VALUES(null, ...), and MySQL replaced the NULL "
    "with the next AUTO_INCREMENT value (read-back id=8, HTTP 200). With AUTO_INCREMENT, an explicit NULL is never stored or rejected, so the NOT NULL predicate cannot be violated through any input. "
    "It works as a structural property of the generated key, not a runtime-testable predicate. The null did reach persistence and was replaced by the database, not rejected.", 0.8,
    ["The outcome taxonomy has no category for database-side value generation. The observation is recorded as structural."])

res("pc-4077068a2bf5", "APPLICATION_REJECTED", True, "application", True, "elegant", ["C03-id-bigint-max", "C03-readback", "V09-id-over-bigint", "V10-id-non-integer"],
    "Predicate 'ums_admin.id has type BIGINT(20)' (signed 64-bit). The client-controlled UmsAdmin.id is a java.lang.Long. V09 (id=9223372036854775808, one past the BIGINT maximum) and V10 (id='abc') were rejected during "
    "Jackson request-body binding with HTTP 400 'out of range of long' / 'not a valid Long value'. No provider call or SQL was issued (no INSERT in the SQL trace). "
    "Boundary C03 (id=9223372036854775000) was accepted and read back unchanged. The Java Long range equals the signed BIGINT range, so the application binding layer enforces exactly this predicate.", 0.85,
    ["The rejection comes from framework type binding (Jackson/Long), not an explicit validator. The 400 body is Spring's default error JSON with parser details."])

res("pc-bcab32ac6f64", "APPLICATION_REJECTED", True, "application", True, "elegant", ["C04-status-int-max-display-width", "C04-readback", "V11-status-over-int", "V12-status-non-integer"],
    "Predicate 'ums_admin.status has type INT(1)'. INT(1) is a signed 32-bit INT, and (1) is only a display width. UmsAdmin.status is a java.lang.Integer. V11 (2147483648) and V12 ('x') were rejected by Jackson "
    "binding with HTTP 400 before any SQL. Boundary C04 (2147483647) was accepted and read back as 2147483647, which confirms the display width does not limit values. The application binding type matches the INT range exactly.", 0.8,
    ["The column comment says status is 0/1, but neither the application nor the DB enforces that. C04 stored 2147483647.",
     "The rejection comes from framework type binding, not explicit validation."])

for tid, col in [("pc-4b80a8cb1221", "create_time"), ("pc-f2ed0251561b", "login_time")]:
    res(tid, "APPLICATION_TRANSFORMED", True, "application", True, "elegant", ["V13-createtime-loginTime-out-of-range", "V13-readback", "V14-createtime-garbage"],
        f"Predicate '{F[tid]['predicate']}'. V13 sent createTime/loginTime='10000-01-01 00:00:00', which is outside the DATETIME range (max 9999-12-31). Jackson's lenient parse accepted it, and "
        f"UmsAdminServiceImpl.initUmsAdmin unconditionally overwrote both fields with new Date(). The SQL trace shows current Timestamps were bound, and read-back V13-readback shows the current server time in {col}. "
        "V14 (a non-date string) was rejected by Jackson with HTTP 400 before persistence. The client-supplied value can never reach the column on the insert path.", 0.85)

# ---- non-exercised
LOGLOG = {x for x, v in F.items() if v["subject"]["table"] == "ums_admin_login_log"}
for tid in LOGLOG:
    res(tid, "BLOCKED_EXTERNAL_DEPENDENCY", False, "not-observed", None, "not-assessed", [],
        f"Predicate '{F[tid]['predicate']}'. The only write path to ums_admin_login_log is POST /user/login (business-oauth2) -> MessageService.sendAdminLoginLog -> RocketMQ topic "
        "admin-login-log-topic -> message-admin-login-log consumer -> UmsAdminLoginLogService.insert. It needs a RocketMQ broker, a Redis-backed OAuth2 token endpoint on a hard-coded localhost:9001, "
        "and an external IP-geolocation call (http://ip.taobao.com) that populates address. The policy does not allow these external services or extra ports. id/admin_id/create_time are also server-generated.", 0.8,
        [], [INV])

for tid, v in F.items():
    if tid in R:
        continue
    t = v["subject"]["table"]
    src = v["sources"][0]["file_path"]
    if t in ("oauth_access_token", "oauth_refresh_token"):
        res(tid, "VARIANT_NOT_DEPLOYED", False, "not-applicable", None, "not-applicable", [],
            f"Predicate '{v['predicate']}' ({src}). These tables would only be written by Spring Security OAuth2 JdbcTokenStore, and that variant is commented out in "
            "AuthorizationServerConfiguration.tokenStore(). The active variant is RedisTokenStore, so no deployable configuration of the code writes this table.", 0.85, [], [INV])
    elif src.endswith("oauth2.sql"):
        res(tid, "NOT_API_CONTROLLABLE", False, "not-applicable", None, "not-applicable", [],
            f"Predicate '{v['predicate']}' ({src}). Table {t} is never written by the application. JdbcClientDetailsService only reads oauth_client_details (no client-registration endpoint is exposed). "
            "No JdbcApprovalStore, JdbcAuthorizationCodeServices, or JdbcClientTokenServices is configured, so clientdetails/oauth_approvals/oauth_code/oauth_client_token have no persistence operation.", 0.85, [], [INV])
    elif v["kind"] == "custom":
        res(tid, "STRUCTURAL_NOT_RUNTIME_PREDICATE", False, "not-applicable", None, "not-applicable", [],
            f"Predicate '{v['predicate']}' ({src}). AUTO_INCREMENT is a key-generation declaration, not a value predicate that a request can violate. Also, no application code writes {t}.", 0.85, [], [INV])
    else:
        res(tid, "NOT_API_CONTROLLABLE", False, "not-applicable", None, "not-applicable", [],
            f"Predicate '{v['predicate']}' ({src}). Table {t} exists in the deployed schema (loaded from docs/sql/mplus.sql), but the application has no entity, mapper, SQL statement, or endpoint that writes it. "
            "Only ums_admin and ums_admin_login_log have @Table domain classes and MyMapper mappers (see inventory). No public API can reach a persistence operation on this table.", 0.85, [], [INV])

targets = [x["finding_id"] for x in d["findings"]]
assert set(targets) == set(R), (len(targets), len(R))
vr = {"schema_version": "persistence-runtime-verification-v2", "application": "funtl_MyShopPlus", "constraint_report_schema_version": "9",
      "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "target_ids": targets, "cases": cases,
      "results": [R[t] for t in targets],
      "warnings": ["The first harness run (evidence in raw/attempt1, logs/attempt1) failed before persistence because the direct Dubbo URL lacked version=1.0.0. It was fixed and all cases were rerun. Only the rerun is used as evidence.",
                   "The runtime database is MySQL 8.0.42 (strict mode) and not the TiDB the project was designed for.",
                   "1116 of 1134 targets are on tables that no application code writes (or only through blocked external infrastructure)."]}
json.dump(vr, open(OUT + "/verification-results.json", "w"), indent=1, ensure_ascii=False)

A = ROOT + "/application"
logs = [ev("logs/build.log", "deployment-log", "Maven build output (quiet mode, exit 0)"),
        ev("logs/mysql-init.log", "deployment-log", "mysqld --initialize-insecure"),
        ev("logs/mysqld-error.log", "database-log", "MySQL server error log"),
        ev("logs/mysql-general-ums_admin.log", "sql-trace", "MySQL general log filtered to ums_admin statements and connects"),
        ev("logs/provider.log", "application-log", "provider-admin-service log (final run, MyBatis DEBUG SQL)"),
        ev("logs/reg.log", "application-log", "business-reg-service log (final run)"),
        ev("logs/provider-attempt1.log", "deployment-log", "First provider start; bound 0.0.0.0 outside namespace and was stopped"),
        ev("logs/provider-attempt2.log", "deployment-log", "Failed attempt with DUBBO_IP_TO_BIND=127.0.0.1 (rejected by Dubbo 2.7.3)"),
        ev("logs/reg-attempt1.log", "deployment-log", "Failed reg start: EchoService reference had no registry/direct URL"),
        ev("logs/reg-attempt2.log", "deployment-log", "Reg run with direct URLs missing version=1.0.0 (attempt1 cases)"),
        ev("logs/harness-run.log", "other", "Harness console output of the final run"),
        ev("logs/start-provider.sh", "other", "Provider start command"),
        ev("logs/start-reg.sh", "other", "Reg service start command"),
        ev("logs/harness.py", "other", "Verification harness")]
W = "/tmp/mysp-verify"
dep = {"schema_version": "persistence-runtime-verification-v2", "application": "funtl_MyShopPlus", "source_revision": None,
       "isolated_application_path": A, "build_system": "maven 3.9.9 (multi-module; built business-reg-service and provider-admin-service with -am)",
       "java_version": "OpenJDK 1.8.0_452 (build and runtime; JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64)",
       "runtime_database": "MySQL 8.0.42 (Ubuntu build), private instance, --skip-networking, Unix socket /tmp/mysp-verify/run/mysql.sock, sql_mode=ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION; database mplus_ums_admin loaded from docs/sql/mplus.sql (71 tables)",
       "schema_context_id": "dbctx-1a1c02a7d585",
       "base_urls": ["http://127.0.0.1:18205"], "ports": [18205, 20882],
       "health_checks": ["GET http://127.0.0.1:18205/actuator/health -> {\"status\":\"UP\"}", "provider log 'Start NettyServer bind /0.0.0.0:20882' inside the loopback-only network namespace", "control case C01 POST /reg -> HTTP 200 with persisted row read back"],
       "commands": [
           {"purpose": "build", "command": "JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 mvn -q -B -DskipTests -pl business/business-reg-service,provider/provider-admin-service -am install", "working_directory": A, "exit_code": 0},
           {"purpose": "fetch junixsocket for Unix-socket JDBC", "command": "mvn -q -B -f /tmp/mysp-verify/pom.xml dependency:copy-dependencies -DexcludeGroupIds=mysql -DoutputDirectory=/tmp/mysp-verify/extlib", "working_directory": W, "exit_code": 0},
           {"purpose": "repackage deploy jars without sentinel-transport-simple-http", "command": "zip -d <jar> BOOT-INF/lib/sentinel-transport-simple-http-1.6.3.jar", "working_directory": W + "/deploy", "exit_code": 0},
           {"purpose": "init database", "command": "mysqld --no-defaults --initialize-insecure --datadir=/tmp/mysp-verify/data", "working_directory": A, "exit_code": 0},
           {"purpose": "start database", "command": "mysqld --no-defaults --datadir=/tmp/mysp-verify/data --socket=/tmp/mysp-verify/run/mysql.sock --skip-networking --mysqlx=OFF --general-log=1 ...", "working_directory": A, "exit_code": None},
           {"purpose": "load schema", "command": "mysql -S /tmp/mysp-verify/run/mysql.sock -uroot -e 'create database mplus_ums_admin default charset utf8' && mysql -S ... mplus_ums_admin < docs/sql/mplus.sql", "working_directory": A, "exit_code": 0},
           {"purpose": "create loopback-only network namespace", "command": "unshare -rn sh -c 'ip link set lo up; exec sleep 100000'", "working_directory": A, "exit_code": None},
           {"purpose": "start provider-admin-service (Dubbo 20882)", "command": "nsenter -t <holder> -U -n --preserve-credentials /tmp/mysp-verify/start-provider.sh (see logs/start-provider.sh)", "working_directory": OUT + "/logs", "exit_code": None},
           {"purpose": "start business-reg-service (HTTP 18205)", "command": "nsenter -t <holder> -U -n --preserve-credentials /tmp/mysp-verify/start-reg.sh (see logs/start-reg.sh)", "working_directory": OUT, "exit_code": None},
           {"purpose": "run verification harness", "command": "nsenter -t <holder> -U -n --preserve-credentials python3 /tmp/mysp-verify/harness.py <output>", "working_directory": OUT, "exit_code": 0},
           {"purpose": "stop", "command": "kill <provider/reg java pids>; kill <namespace holder>; mysqladmin -S /tmp/mysp-verify/run/mysql.sock -uroot shutdown", "working_directory": OUT, "exit_code": 0}],
       "patches": [PATCH], "logs": logs, "cleanup_performed": True,
       "notes": ["No application source files were modified. All adjustments are packaging, classpath, or command-line configuration (patches/deployment-compat.txt).",
                 "Nacos, Sentinel dashboard, Redis, RocketMQ, TiDB, the OAuth2 server, and the profile/gateway/upload/message services were not deployed (external services or extra ports would be needed).",
                 "All processes started for this run (private mysqld, both JVMs, namespace holder) were stopped. The pre-existing system mysqld (pid 1677) was not touched. Temporary data remains under /tmp/mysp-verify."]}
json.dump(dep, open(OUT + "/deployment.json", "w"), indent=1, ensure_ascii=False)
import collections
print(collections.Counter(r["outcome"] for r in vr["results"]))
