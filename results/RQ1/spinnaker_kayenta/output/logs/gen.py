import json, hashlib, os, datetime
OUT="/artifact/results/RQ1/spinnaker_kayenta/spinnaker_kayenta-20260929T162038Z-8d598796/output"
APP="/artifact/results/RQ1/spinnaker_kayenta/spinnaker_kayenta-20260929T162038Z-8d598796/application"
def sha(p): return hashlib.sha256(open(os.path.join(OUT,p),'rb').read()).hexdigest()
def ev(p,kind,desc): return {"path":p,"kind":kind,"description":desc,"sha256":sha(p)}
summ=json.load(open(f"{OUT}/raw/_case-summary.json"))
BASE="http://127.0.0.1:18204"

cases=[]; casefiles={}
for f in sorted(os.listdir(f"{OUT}/raw")):
    if not f.endswith('.json') or f.startswith('_'): continue
    r=json.load(open(f"{OUT}/raw/{f}")); cid=r['case_id']
    s=summ[cid]
    reached = any(l.split(': ',1)[-1].startswith(('insert','update')) for l in s['log_sql']) if s['log_sql'] else False
    obs_parts=[f"HTTP {r['response']['status']}"]
    if s['log_errors']: obs_parts.append("log: "+ " || ".join(e.split(': ',1)[-1][:160] for e in s['log_errors'][:3]))
    if s['log_sql']: obs_parts.append("SQL: "+ "; ".join(l.split(': ',1)[-1][:60] for l in s['log_sql']))
    if r.get('readback_result'): obs_parts.append("read-back: "+ r['readback_result'].replace('\n',' | ')[:300])
    e=[ev(f"raw/{f}","http-exchange","Full request/response exchange with MySQL read-back"),
       ev(f"logs/cases/{cid}.log","application-log","Application log slice (Hibernate SQL, bindings, exceptions) captured during this case")]
    os.makedirs(f"{OUT}/raw/readback",exist_ok=True)
    if r.get('readback_result'):
        rp=f"raw/readback/{cid}.txt"
        open(f"{OUT}/{rp}","w").write("-- MySQL read-back executed immediately after the request\n-- SQL: "+r['readback_sql']+"\n"+r['readback_result']+"\n")
        e.append(ev(rp,"read-back","Direct MySQL read-back of persisted state after this case"))
    elif r['purpose']=='read-back':
        rp=f"raw/readback/{cid}.txt"
        open(f"{OUT}/{rp}","w").write("-- API read-back: "+r['request']['method']+" "+r['request']['url']+"\n-- HTTP "+str(r['response']['status'])+"\n"+r['response']['body']+"\n")
        e.append(ev(rp,"read-back","API read-back (GET) of the persisted object loaded from MySQL via SqlStorageService.loadObject"))
    cases.append({"case_id":cid,"purpose":r['purpose'],"target_ids":r['target_ids'],"endpoint":r['request']['url'].replace(BASE,'').split('?')[0],
        "request_method":r['request']['method'],"request_url":r['request']['url'] if len(r['request']['url'])<400 else r['request']['url'][:120]+"...(truncated; full URL in raw exchange)",
        "response_status":r['response']['status'],"reached_persistence":reached if r['purpose']!='read-back' else False,
        "evidence":e,"observation":"; ".join(obs_parts)})
    casefiles[cid]=e
def E(*cids):
    out=[]
    for c in cids: out+=casefiles[c]
    return out
schema=ev("logs/schema-mysql.txt","database-log","SHOW CREATE TABLE output of Liquibase-created MySQL schema and DATABASECHANGELOG (postgres changeset MARK_RAN)")
import shutil
def src(p,d):
    dst=os.path.join(OUT,"source",p); os.makedirs(os.path.dirname(dst),exist_ok=True)
    shutil.copyfile(os.path.join(APP,p),dst)
    return ev("source/"+p,"source",d+" (copy of application source file "+p+")")
SVC="kayenta-sql/src/main/java/com/netflix/kayenta/sql/storage/SqlStorageService.java"
final=ev("raw/final-db-readback.tsv","read-back","Final state of all four tables after all cases")

R=[]
def add(tid,kind,outcome,conf_pred,obs,appl,handling,cids,evid,rat,conf,lim):
    R.append({"target_id":tid,"target_kind":kind,"outcome":outcome,"exact_predicate_confirmed":conf_pred,"observed_enforcement":obs,
      "application_layer_implemented":appl,"response_handling":handling,"case_ids":cids,"evidence":evid,"rationale":rat,"confidence":conf,"limitations":lim})

# id length / varchar type: canary_config & canary_archive
for tid,tbl,pref in [("pc-900bdfd125e0","canary_config","CC"),("pc-d4dc77dfb22b","canary_config","CC"),("pc-cf94e5cb7efc","canary_archive","CA"),("pc-11859c35fe9a","canary_archive","CA")]:
    what="has length 255" if tid in("pc-900bdfd125e0","pc-cf94e5cb7efc") else "has type VARCHAR(255)"
    path="POST /canaryConfig (body field id)" if pref=="CC" else "POST /canaryResultArchive (query param pipelineId)"
    add(tid,"constraint","DATABASE_ENFORCED_UNHANDLED",True,"database",False,"unhandled",[f"{pref}-01-control-create",f"{pref}-03-boundary-id-255",f"{pref}-04-violation-id-256"],
        E(f"{pref}-01-control-create",f"{pref}-03-boundary-id-255",f"{pref}-04-violation-id-256")+[schema],
        f"{tbl}.id {what}. The id is client-controlled via {path}. A 255-character id was persisted (read-back CHAR_LENGTH=255). A 256-character id passed all application checks, Hibernate issued 'insert into {tbl}', and MySQL (strict mode) rejected it with SQL Error 1406/22001 'Data too long for column id'; Spring translated it to DataIntegrityViolationException and kork's generic handler returned HTTP 500 'Internal Server Error' exposing the exception class. Read-back shows no row persisted. The application has no length validation.",
        0.95,["Behaviour depends on MySQL STRICT_TRANS_TABLES (enabled, default); non-strict MySQL would silently truncate."])
# PK canary_config / ORM PK / canary_archive PK
add("pc-82610b8aefc0","constraint","APPLICATION_REJECTED",True,"application",True,"elegant",
    ["CC-01-control-create","CC-05-violation-duplicate-id","CC-06-boundary-duplicate-id-case-variant","CC-07-update-same-id"],
    E("CC-01-control-create","CC-05-violation-duplicate-id","CC-06-boundary-duplicate-id-case-variant","CC-07-update-same-id")+[schema],
    "canary_config.id identifies a row. After creating cc-valid-001, a second POST with the same id was rejected by the controller's existence pre-check (loadObject -> findById) with HTTP 400 \"Canary config 'cc-valid-001' already exists.\"; only a SELECT was issued (no INSERT) and read-back shows the original row unchanged. PUT on the same id issued an UPDATE (row count stays 1), consistent with id identifying the row. The DB PK itself was never reached by the duplicate insert.",
    0.9,["The case-variant id 'CC-VALID-001' was also rejected because the MySQL utf8mb4_0900_ai_ci collation makes the PK/lookup case-insensitive - stricter than exact-string identity; this is deployed-schema behaviour, not the extracted predicate.","Concurrent duplicate POSTs (race past the pre-check) were not tested; JPA save() would merge rather than fail."])
add("pc-5a7d64fe7c3a","constraint","APPLICATION_REJECTED",True,"application",True,"elegant",
    ["CC-01-control-create","CC-05-violation-duplicate-id","CC-07-update-same-id","CA-05-violation-duplicate-id","CA-06-update-same-id"],
    E("CC-05-violation-duplicate-id","CC-07-update-same-id","CA-05-violation-duplicate-id","CA-06-update-same-id")+[src("kayenta-sql/src/main/java/com/netflix/kayenta/sql/storage/model/SqlBaseObject.java","@Id String id on @MappedSuperclass")],
    "ORM @Id on SqlBaseObject.id (inherited by all four entities). Exercised through canary_config and canary_archive: duplicate-id creates were rejected by application existence checks with HTTP 400 (no INSERT issued); PUT with an existing id caused Hibernate merge -> 'update ... where id=?' and read-back shows exactly one row, i.e. id identifies the persistent row.",
    0.85,["metric_sets/metric_set_pairs ids are always server-generated UUIDs and could not be duplicated via the API.","Id is application-assigned (no generator); JPA save() merges on an existing id, so identity is enforced by the controllers' pre-checks rather than the ORM for create paths."])
add("pc-000a33b9c80b","constraint","APPLICATION_REJECTED",True,"application",True,"elegant",
    ["CA-01-control-create","CA-05-violation-duplicate-id","CA-06-update-same-id"],E("CA-01-control-create","CA-05-violation-duplicate-id","CA-06-update-same-id")+[schema],
    "canary_archive.id identifies a row. A second POST /canaryResultArchive?pipelineId=ca-valid-001 was rejected with HTTP 400 \"Archived canary result 'ca-valid-001' already exists.\" after only a SELECT; read-back shows original content (application=verifapp). PUT on the same id updated the single row (count 1).",
    0.9,["DB PK violation itself not reached; concurrent duplicate creation not tested.","Lookup is case-insensitive under utf8mb4_0900_ai_ci collation."])
# not null id: transformed
add("pc-03e7ed0064f7","constraint","APPLICATION_TRANSFORMED",True,"application",True,"elegant",["CC-08-violation-null-id","CC-09-violation-empty-id"],
    E("CC-08-violation-null-id","CC-09-violation-empty-id")+[final],
    "canary_config.id must not be null. POST /canaryConfig with id omitted (null) and with id \"\" both returned 200; the controller replaces an empty id with UUID.randomUUID() before storeObject. Read-back shows rows with 36-char UUID ids (also written into content.id), so a null id never reaches the INSERT.",
    0.9,["No path found that passes a null id to storage; PUT uses a non-null path variable."])
add("pc-3c41052834d2","constraint","APPLICATION_TRANSFORMED",True,"application",True,"elegant",["CA-07-violation-null-id"],E("CA-07-violation-null-id")+[final],
    "canary_archive.id must not be null. POST /canaryResultArchive without pipelineId returned 200 with a generated UUID; the controller sets pipelineId = UUID.randomUUID() when null. Read-back shows the row with a 36-char UUID id.",
    0.9,["PUT path uses a mandatory non-null path variable."])
# metric_sets / metric_set_pairs id-related: not controllable
for tid,tbl,pref,d in [("pc-b2886370da3b","metric_sets","MS","length 255"),("pc-bcfeaadde2a6","metric_sets","MS","not-null"),("pc-f2aa380a79e9","metric_sets","MS","primary key"),("pc-34efbcce606b","metric_sets","MS","VARCHAR(255) type"),
                       ("pc-a56ff232d178","metric_set_pairs","MSP","length 255"),("pc-25e267f034f9","metric_set_pairs","MSP","not-null"),("pc-5f7f9ca6c44d","metric_set_pairs","MSP","primary key"),("pc-88c6ef457170","metric_set_pairs","MSP","VARCHAR(255) type")]:
    ep="/metricSetList" if pref=="MS" else "/metricSetPairList"
    add(tid,"constraint","NOT_API_CONTROLLABLE",False,"not-applicable",None,"not-applicable",[f"{pref}-01-control-create"],E(f"{pref}-01-control-create")+[src(SVC,"storeObject sets id from objectKey")],
        f"{tbl}.id {d}: every write path (POST {ep}, and internal metric-fetch/judge tasks) uses a server-generated UUID.randomUUID() as the id, so a client cannot supply a null, over-long, non-string or duplicate id. Control shows a 36-char UUID persisted.",
        0.85,["Only the public HTTP API was considered; the StorageDataMigrator (config-driven) was not exercised."])
# created_at/updated_at not-null & datetime type
ts=[("pc-89d1cd05bf3c","canary_archive","created_at","must not be null","CA"),("pc-89db031a1827","canary_archive","updated_at","must not be null","CA"),
    ("pc-343b4ffdfac5","canary_archive","created_at","has type datetime","CA"),("pc-990df09fb055","canary_archive","updated_at","has type datetime","CA"),
    ("pc-03dd49ea23ba","canary_config","created_at","must not be null","CC"),("pc-454b6220f809","canary_config","updated_at","must not be null","CC"),
    ("pc-cd98250264a6","canary_config","created_at","has type datetime","CC"),("pc-e3c4f3bbce3b","canary_config","updated_at","has type datetime","CC"),
    ("pc-aadee8576d99","metric_sets","created_at","must not be null","MS"),("pc-4ee8f253c4e1","metric_sets","updated_at","must not be null","MS"),
    ("pc-4ff0c7f191dd","metric_sets","created_at","has type datetime","MS"),("pc-0a2ac553dd29","metric_sets","updated_at","has type datetime","MS"),
    ("pc-893aeb4d6f06","metric_set_pairs","created_at","must not be null","MSP"),("pc-6e7266c1819b","metric_set_pairs","updated_at","must not be null","MSP"),
    ("pc-914538813632","metric_set_pairs","created_at","has type datetime","MSP"),("pc-216b2a3dbc5e","metric_set_pairs","updated_at","has type datetime","MSP")]
for tid,tbl,col,d,pref in ts:
    add(tid,"constraint","NOT_API_CONTROLLABLE",False,"not-applicable",None,"not-applicable",[f"{pref}-01-control-create"],E(f"{pref}-01-control-create")+[src(SVC,"storeObject sets createdAt/updatedAt = Instant.now()")],
        f"{tbl}.{col} {d}: SqlStorageService.storeObject always sets createdAt and updatedAt to Instant.now(); no request field maps to these columns (client-supplied createdTimestamp in canary configs only affects the JSON content). Control read-back shows a server-generated DATETIME value.",
        0.9,["Observed that MySQL DATETIME (no fractional precision) stores Instant values truncated to seconds; this is deployed-schema behaviour, not a predicate violation."])
# content not-null
for tid,tbl,pref,cc in [("pc-b223c202dd17","canary_archive","CA","CA-08-violation-null-content"),("pc-697814377ac0","canary_config","CC","CC-10-violation-null-content"),
                        ("pc-2b8c47e5d7bd","metric_sets","MS","MS-02-violation-null-content"),("pc-c69dfeadd911","metric_set_pairs","MSP","MSP-02-violation-null-content")]:
    add(tid,"constraint","NOT_API_CONTROLLABLE",False,"not-applicable",None,"not-applicable",[f"{pref}-01-control-create",cc],E(f"{pref}-01-control-create",cc),
        f"{tbl}.content must not be null: content is always ObjectMapper.writeValueAsString(obj) of the bound request body, which is never SQL NULL. The closest API attempt (JSON body literal null) was rejected by Spring request-body binding with HTTP 400 before the controller ran (no SQL issued, row count unchanged); that is a binding failure, not enforcement of this predicate.",
        0.85,["A null domain object would serialize to the JSON text 'null', not SQL NULL, so the column predicate is unreachable from the API."])
# content JSON type
for tid,tbl,pref in [("pc-fdc864d03407","canary_archive","CA"),("pc-28c967fd981a","canary_config","CC"),("pc-2611c9ac3275","metric_sets","MS"),("pc-ab279b731a74","metric_set_pairs","MSP")]:
    add(tid,"constraint","NOT_API_CONTROLLABLE",False,"not-applicable",None,"not-applicable",[f"{pref}-01-control-create"],E(f"{pref}-01-control-create")+[schema],
        f"{tbl}.content has type JSON (deployed as MySQL json). Content is produced exclusively by Jackson serialization of a typed request object, so the client cannot make the application write non-JSON text. Control read-back: JSON_VALID(content)=1.",
        0.8,["MySQL-specific JSON limits (e.g. max nesting depth 100) were not probed; the typed request models expose no free-form deeply nested fields."])
# JSONB
for tid,tbl in [("pc-fdf41b7b35f8","canary_archive"),("pc-76e10d4548d7","canary_config"),("pc-044910f711c0","metric_set_pairs"),("pc-a0ad056986da","metric_sets")]:
    add(tid,"constraint","VARIANT_NOT_DEPLOYED",False,"not-applicable",None,"not-applicable",[],[schema],
        f"{tbl}.content JSONB comes from the postgresql-only changeset (dbms precondition, onFail MARK_RAN). The deployment used MySQL 8.0.42 (no PostgreSQL server available locally and no permitted port for one), where Liquibase marked the changeset as ran without applying it; the column is MySQL json.",
        0.95,["PostgreSQL variant not exercised."])
# deps
for tid,ent in [("dep-66b9ecab929e","SqlCanaryArchive"),("dep-60bfac11e620","SqlCanaryConfig"),("dep-4f212f5e936f","SqlMetricSetPairs"),("dep-934e5c07c2b4","SqlMetricSets")]:
    add(tid,"dependency","STRUCTURAL_NOT_RUNTIME_PREDICATE",False,"not-applicable",None,"not-applicable",[],[src(f"kayenta-sql/src/main/java/com/netflix/kayenta/sql/storage/model/{ent}.java",f"{ent} extends SqlBaseObject")],
        f"ORM inheritance dependency {ent} -> SqlBaseObject (@MappedSuperclass). This is a structural mapping relationship with no runtime-violable predicate; its effect (inherited id/content/created_at/updated_at columns) was observed indirectly in the Hibernate INSERT statements of the control cases.",
        0.95,[])

targets=["pc-5a7d64fe7c3a","pc-cf94e5cb7efc","pc-b223c202dd17","pc-89d1cd05bf3c","pc-3c41052834d2","pc-89db031a1827","pc-000a33b9c80b","pc-fdc864d03407","pc-343b4ffdfac5","pc-11859c35fe9a","pc-990df09fb055","pc-900bdfd125e0","pc-697814377ac0","pc-03dd49ea23ba","pc-03e7ed0064f7","pc-454b6220f809","pc-82610b8aefc0","pc-28c967fd981a","pc-cd98250264a6","pc-d4dc77dfb22b","pc-e3c4f3bbce3b","pc-b2886370da3b","pc-2b8c47e5d7bd","pc-aadee8576d99","pc-bcfeaadde2a6","pc-4ee8f253c4e1","pc-f2aa380a79e9","pc-2611c9ac3275","pc-4ff0c7f191dd","pc-34efbcce606b","pc-0a2ac553dd29","pc-a56ff232d178","pc-c69dfeadd911","pc-893aeb4d6f06","pc-25e267f034f9","pc-6e7266c1819b","pc-5f7f9ca6c44d","pc-ab279b731a74","pc-914538813632","pc-88c6ef457170","pc-216b2a3dbc5e","pc-fdf41b7b35f8","pc-76e10d4548d7","pc-044910f711c0","pc-a0ad056986da","dep-66b9ecab929e","dep-60bfac11e620","dep-4f212f5e936f","dep-934e5c07c2b4"]
ids=[r['target_id'] for r in R]
assert sorted(ids)==sorted(targets) and len(ids)==len(set(ids)), set(targets)^set(ids)
R.sort(key=lambda r: targets.index(r['target_id']))
now=datetime.datetime.now(datetime.timezone.utc).isoformat()
vr={"schema_version":"persistence-runtime-verification-v2","application":"spinnaker_kayenta","constraint_report_schema_version":"9","generated_at":now,
    "target_ids":targets,"cases":cases,"results":R,
    "warnings":["Two compatibility-only patches were applied (patches/kayenta-sql-harness.patch): junixsocket runtime dependency so JDBC can use a unix socket (no DB TCP port was permitted), and a harness configuration that registers a deterministic SQL storage account name + account credentials, because upstream SqlStorageService receives account names via an injected List<String> containing only a random currentInstanceId, making SQL storage unroutable. No persistence logic was changed.",
                "Runtime database is MySQL 8.0.42 (default schema context); PostgreSQL JSONB variant not deployed."]}
json.dump(vr,open(f"{OUT}/verification-results.json","w"),indent=2)

B="/tmp/kayenta-verif-8d598796"
dep={"schema_version":"persistence-runtime-verification-v2","application":"spinnaker_kayenta","source_revision":None,"isolated_application_path":APP,
 "build_system":"gradle 7.6.1 (wrapper)","java_version":"OpenJDK 17.0.15 (/usr/lib/jvm/java-17-openjdk-amd64)",
 "runtime_database":"MySQL 8.0.42 (Ubuntu build, private instance, skip-networking, unix socket only, STRICT_TRANS_TABLES, utf8mb4_0900_ai_ci); schema created by the application's Liquibase changelog",
 "schema_context_id":"dbctx-9ed09ac67b2d","base_urls":["http://127.0.0.1:18204"],"ports":[18204,16379],
 "health_checks":["GET http://127.0.0.1:18204/health -> 200 {\"status\":\"UP\", db: MySQL UP}","GET http://127.0.0.1:18204/credentials -> sql-account [CONFIGURATION_STORE, OBJECT_STORE]","redis-cli -p 16379 ping -> PONG"],
 "commands":[
  {"purpose":"build","command":"JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 ./gradlew --no-daemon :kayenta-web:installDist -x test","working_directory":APP,"exit_code":0},
  {"purpose":"fetch redis (dependency download)","command":"apt-get download redis-server redis-tools lua-cjson lua-bitop libjemalloc2 libhiredis0.14 liblua5.1-0 && dpkg -x <deb> x","working_directory":f"{B}/redis","exit_code":0},
  {"purpose":"start redis","command":"LD_LIBRARY_PATH=x/usr/lib/x86_64-linux-gnu:x/usr/lib/x86_64-linux-gnu/lua/5.1 x/usr/bin/redis-server --bind 127.0.0.1 --port 16379 --save '' --appendonly no --daemonize yes --pidfile redis.pid --logfile <output>/logs/redis.log","working_directory":B,"exit_code":0},
  {"purpose":"init mysql (binary copied out of /usr/sbin to avoid the AppArmor profile that blocks non-standard datadirs)","command":"cp /usr/sbin/mysqld mysqld-bin && ./mysqld-bin --defaults-file=mysql/my.cnf --initialize-insecure","working_directory":B,"exit_code":0},
  {"purpose":"start mysql","command":"./mysqld-bin --defaults-file=mysql/my.cnf &  (skip-networking, socket=mysql/run/mysqld.sock, general_log on)","working_directory":B,"exit_code":0},
  {"purpose":"create db/user","command":"mysql -S mysql/run/mysqld.sock -uroot -e \"CREATE DATABASE kayenta; CREATE USER 'kayenta'@'localhost' IDENTIFIED WITH mysql_native_password BY 'kayenta'; GRANT ALL ON kayenta.* TO 'kayenta'@'localhost'\"","working_directory":B,"exit_code":0},
  {"purpose":"start application","command":"JAVA_OPTS=-Xmx1g bin/kayenta --spring.config.additional-location=file:/tmp/kayenta-verif-8d598796/harness.yml (copy: logs/kayenta-harness-config.yml)","working_directory":f"{APP}/kayenta-web/build/install/kayenta","exit_code":None},
  {"purpose":"run verification cases","command":"python3 /tmp/kayenta-verif-8d598796/run_cases.py","working_directory":APP,"exit_code":0},
  {"purpose":"stop application","command":"kill <wrapper pid>; kill <java pid 1164260>","working_directory":APP,"exit_code":0},
  {"purpose":"stop mysql","command":"mysqladmin -S mysql/run/mysqld.sock -uroot shutdown","working_directory":B,"exit_code":0},
  {"purpose":"stop redis","command":"kill $(cat redis.pid)","working_directory":B,"exit_code":0}],
 "patches":[ev("patches/kayenta-sql-harness.patch","patch","Compatibility-only: junixsocket runtime deps in kayenta-sql.gradle; new HarnessSqlAccountConfiguration registering account 'sql-account' (String bean consumed by SqlStorageService's List<String> accountNames + CONFIGURATION_STORE/OBJECT_STORE credentials). No change to persistence code.")],
 "logs":[ev("logs/build.log","deployment-log","Gradle build output"),ev("logs/kayenta-app.log","application-log","Full application log incl. Liquibase, Hibernate SQL and bind parameters"),
         ev("logs/kayenta-harness-config.yml","deployment-log","Harness Spring configuration"),ev("logs/schema-mysql.txt","database-log","Deployed schema"),
         ev("logs/mysql-general.log","database-log","MySQL general query log"),ev("logs/mysql-error.log","database-log","MySQL error log"),ev("logs/redis.log","deployment-log","Redis log")],
 "cleanup_performed":True,
 "notes":["Kayenta, MySQL and Redis processes started by this run were all stopped; no listeners remain on 18204/16379.",
          "MySQL used no TCP port (skip-networking); JDBC connected over a unix socket via junixsocket, so only the permitted ports 18204 and 16379 were bound.",
          "Temporary runtime state (MySQL datadir, Redis binaries, harness scripts) left under /tmp/kayenta-verif-8d598796 (stopped, non-running)."]}
json.dump(dep,open(f"{OUT}/deployment.json","w"),indent=2)
from collections import Counter; print(Counter(r['outcome'] for r in R), len(cases))
