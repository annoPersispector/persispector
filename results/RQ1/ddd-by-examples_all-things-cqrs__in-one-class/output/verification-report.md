# Runtime persistence verification: ddd-by-examples_all-things-cqrs__in-one-class

## Summary

- Targets: 18
- Results: 18
- Exact predicates confirmed: 5
- Runtime database: H2 1.4.197 in-memory (jdbc:h2:mem:testdb), schema.sql + data.sql executed by Spring Boot datasource initializer, ddl-auto=none
- Schema context: dbctx-2c246b7230ae
- Cleanup performed: yes

| Outcome | Count |
| --- | ---: |
| `APPLICATION_REJECTED` | 2 |
| `DATABASE_ENFORCED_UNHANDLED` | 3 |
| `INCONCLUSIVE_PRE_PERSISTENCE_FAILURE` | 4 |
| `NOT_API_CONTROLLABLE` | 8 |
| `STRUCTURAL_NOT_RUNTIME_PREDICATE` | 1 |

## Findings

| Target | Declaration | Outcome | Confirmed | Enforcement | App implementation | Response handling | Confidence | Cases | Rationale |
| --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |
| `pc-578d46063b01` | primary-key: id identifies the persistent row | `STRUCTURAL_NOT_RUNTIME_PREDICATE` | no | not-applicable | not assessed | not-applicable | 0.90 | `c01-control-valid-withdrawal`, `rb-01-after-control` | ORM identity declaration (@Id @GeneratedValue UUID on Withdrawal.id) is a structural mapping fact, not a runtime-violable value predicate; Hibernate generates the id (observed generated UUID in insert bind trace) and no request field maps to it. |
| `pc-c5c47a3dbf1c` | not-null: CREDIT_CARD.INITIAL_LIMIT must not be null | `NOT_API_CONTROLLABLE` | no | not-observed | not assessed | not-applicable | 0.90 | `rb-00-initial`, `c01-control-valid-withdrawal` | CREDIT_CARD.INITIAL_LIMIT NOT NULL cannot be violated via API. No public endpoint creates or modifies CREDIT_CARD rows other than the computed USED_LIMIT update; the only card is seeded by data.sql and INITIAL_LIMIT is re-bound from the loaded entity (10000.00) on every update. |
| `pc-73e8caf08064` | not-null: CREDIT_CARD.USED_LIMIT must not be null | `NOT_API_CONTROLLABLE` | no | not-observed | not assessed | not-applicable | 0.85 | `c01-control-valid-withdrawal`, `c03-amount-null` | USED_LIMIT is always computed as usedLimit.add(amount) from a non-null seed (0); it can never become null. Supplying amount=null (c03) fails with NullPointerException in the domain balance check before any write, so USED_LIMIT=null is not reachable through the API. |
| `pc-3f13f3893d75` | precision-scale: CREDIT_CARD.INITIAL_LIMIT has precision/scale 18/2 | `NOT_API_CONTROLLABLE` | no | not-observed | not assessed | not-applicable | 0.90 | `rb-00-initial`, `c01-control-valid-withdrawal` | CREDIT_CARD.INITIAL_LIMIT precision/scale 18/2 cannot be exercised. No public endpoint creates or modifies CREDIT_CARD rows other than the computed USED_LIMIT update; the only card is seeded by data.sql and INITIAL_LIMIT is re-bound from the loaded entity (10000.00) on every update. |
| `pc-2d38e685b482` | precision-scale: CREDIT_CARD.USED_LIMIT has precision/scale 18/2 | `DATABASE_ENFORCED_UNHANDLED` | yes | database | no | unhandled | 0.90 | `c12-amount-precision-boundary-control`, `c13-used-limit-precision-overflow`, `rb-08-after-used-limit-overflow`, `rb-09-card-after-used-limit-overflow`, `c08-amount-scale-3dp`, `c09-amount-scale-3dp-down`, `rb-03-card-after-scale` | With the withdrawal amount itself in range, the computed USED_LIMIT -17999999999999986.99 exceeded DECIMAL(18,2); H2 rejected the UPDATE (22001 Value too long for column USED_LIMIT DECIMAL(18, 2)), the transaction rolled back (read-back unchanged, no withdrawal row) and the client received a generic 500 DataException. Boundary control at 16 integer digits was accepted. The application has no precision check (negative amounts pass the balance check). |
| `pc-78f815ebd8bd` | primary-key: CREDIT_CARD.ID identifies a row | `NOT_API_CONTROLLABLE` | no | not-observed | not assessed | not-applicable | 0.90 | `rb-00-initial` | CREDIT_CARD.ID primary key cannot be violated: there is no card-creation endpoint and the card id in requests is only used for lookup (findById). |
| `pc-c029559355f4` | type: CREDIT_CARD.ID has type UUID | `NOT_API_CONTROLLABLE` | no | not-observed | not assessed | not-applicable | 0.85 | `rb-00-initial`, `c06-card-not-uuid` | No API writes CREDIT_CARD.ID. A non-UUID card reference is rejected by Jackson binding (c06), but that is a lookup parameter, not a write to CREDIT_CARD.ID. |
| `pc-3baf2fef4297` | type: CREDIT_CARD.INITIAL_LIMIT has type DECIMAL(18, 2) | `NOT_API_CONTROLLABLE` | no | not-observed | not assessed | not-applicable | 0.90 | `rb-00-initial`, `c01-control-valid-withdrawal` | CREDIT_CARD.INITIAL_LIMIT type DECIMAL(18,2) cannot be exercised. No public endpoint creates or modifies CREDIT_CARD rows other than the computed USED_LIMIT update; the only card is seeded by data.sql and INITIAL_LIMIT is re-bound from the loaded entity (10000.00) on every update. |
| `pc-a2c24ce96c78` | type: CREDIT_CARD.USED_LIMIT has type DECIMAL(18, 2) | `DATABASE_ENFORCED_UNHANDLED` | yes | database | no | unhandled | 0.85 | `c12-amount-precision-boundary-control`, `c13-used-limit-precision-overflow`, `rb-09-card-after-used-limit-overflow`, `rb-03-card-after-scale` | USED_LIMIT is a Java BigDecimal computed server-side, so only out-of-range numeric values can violate DECIMAL(18,2); such a value was rejected by H2 (22001) on UPDATE credit_card and surfaced as a generic 500. |
| `pc-d422ab0eead2` | foreign-key: Columns CARD_ID reference CREDIT_CARD(ID) | `INCONCLUSIVE_PRE_PERSISTENCE_FAILURE` | no | not-observed | yes | unhandled | 0.90 | `c05-card-nonexistent-fk`, `c01-control-valid-withdrawal` | The application implements an explicit existence check: WithdrawalProcess calls findById(...).orElseThrow and throws IllegalStateException 'Cannot find card with id ...' before any INSERT. The SQL trace (c05) shows only the SELECT. The failure surfaces as an unhandled HTTP 500 Internal Server Error, not a client-error rejection, so it counts as a pre-persistence failure, not an elegant application rejection. The database FK was never reached. |
| `pc-73e9479cc046` | not-null: WITHDRAWAL.AMOUNT must not be null | `INCONCLUSIVE_PRE_PERSISTENCE_FAILURE` | no | not-observed | yes | unhandled | 0.75 | `c03-amount-null`, `c01-control-valid-withdrawal` | amount=null never reaches the INSERT. CreditCard.withdraw evaluates availableBalance().compareTo(null), which throws a NullPointerException, and the client gets a generic 500 'No message available'. The SQL trace shows no write. This is an accidental failure before persistence, not a deliberate not-null rejection, and the DB NOT NULL was never reached. |
| `pc-c93d051c414e` | not-null: WITHDRAWAL.CARD_ID must not be null | `INCONCLUSIVE_PRE_PERSISTENCE_FAILURE` | no | not-observed | yes | unhandled | 0.80 | `c04-card-null`, `c01-control-valid-withdrawal` | card=null fails in Spring Data findById(null) with IllegalArgumentException 'The given id must not be null!' before any write, and the client gets a generic HTTP 500. The DB NOT NULL on WITHDRAWAL.CARD_ID was never reached, because persisted CARD_ID is always copied from a loaded card id. |
| `pc-7a81073c57bc` | precision-scale: WITHDRAWAL.AMOUNT has precision/scale 18/2 | `DATABASE_ENFORCED_UNHANDLED` | yes | database | no | unhandled | 0.90 | `c11-amount-precision-overflow`, `rb-04-after-amount-overflow`, `rb-05-card-after-amount-overflow`, `c12-amount-precision-boundary-control`, `rb-06-after-boundary-control`, `c08-amount-scale-3dp`, `c09-amount-scale-3dp-down`, `c10-readback-withdrawals`, `rb-02-after-scale` | amount -12345678901234567 passed the application balance check (negative amounts allowed) and reached INSERT into withdrawal, where H2 raised 22001 'Value too long for column AMOUNT DECIMAL(18, 2)'; transaction rolled back (no row) and client got generic 500 DataException. Boundary value with 16 integer digits was accepted and persisted. |
| `pc-20303ffe4698` | primary-key: WITHDRAWAL.ID identifies a row | `NOT_API_CONTROLLABLE` | no | not-observed | not assessed | not-applicable | 0.90 | `c01-control-valid-withdrawal`, `rb-01-after-control` | WITHDRAWAL.ID is generated by Hibernate (@GeneratedValue UUID); WithdrawalCommand has no id field, so a duplicate primary key cannot be requested. |
| `pc-f4259ca21b01` | type: WITHDRAWAL.AMOUNT has type DECIMAL(18, 2) | `APPLICATION_REJECTED` | yes | application | yes | elegant | 0.80 | `c07-amount-not-decimal`, `c11-amount-precision-overflow`, `c01-control-valid-withdrawal` | A non-decimal amount ('abc') is rejected by Jackson binding into java.math.BigDecimal with 400 Bad Request and a descriptive message before persistence. Numeric values out of the DECIMAL(18,2) range are not checked by the application and are rejected by the database (c11, see pc-7a81073c57bc). |
| `pc-a96b949d55f3` | type: WITHDRAWAL.CARD_ID has type UUID | `APPLICATION_REJECTED` | yes | application | yes | elegant | 0.85 | `c06-card-not-uuid`, `c01-control-valid-withdrawal` | A non-UUID card value is rejected by Jackson binding into java.util.UUID with 400 Bad Request before any SQL; CARD_ID values written are always UUIDs of a loaded card. |
| `pc-9d6bb68ddecd` | type: WITHDRAWAL.ID has type UUID | `NOT_API_CONTROLLABLE` | no | not-observed | not assessed | not-applicable | 0.90 | `c01-control-valid-withdrawal` | WITHDRAWAL.ID is always a Hibernate-generated java.util.UUID; no client input reaches it. |
| `dep-6b92cefdf4cd` | foreign-key: WITHDRAWAL -> CREDIT_CARD | `INCONCLUSIVE_PRE_PERSISTENCE_FAILURE` | no | not-observed | yes | unhandled | 0.90 | `c05-card-nonexistent-fk`, `c01-control-valid-withdrawal` | This is the same FK WITHDRAWAL.CARD_ID -> CREDIT_CARD.ID as pc-d422ab0eead2. A nonexistent card is stopped by the explicit lookup plus IllegalStateException before the INSERT, but it surfaces as an unhandled HTTP 500, so the outcome is a pre-persistence failure. The DB FK was never reached. The valid control persisted card_id referencing the seeded card. |

## Deployment

- Base URLs: `http://127.0.0.1:18207`

| Purpose | Working directory | Command | Exit |
| --- | --- | --- | ---: |
| build | `../application` | `JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 mvn -q -B -DskipTests package` | 0 |
| start | `../application` | `/usr/lib/jvm/java-8-openjdk-amd64/bin/java -jar target/in-one-class-0.0.1-SNAPSHOT.jar --server.port=18207 --server.address=127.0.0.1 --spring.jpa.show-sql=true --logging.level.org.hibernate.type.descriptor.sql.BasicBinder=TRACE --logging.level.org.hibernate.SQL=DEBUG > logs/app.log` | — |
| health-check | `.` | `curl -s http://127.0.0.1:18207/actuator/health` | 0 |
| test-driver | `.` | `python3 raw/harness.py (cases fed on stdin)` | 0 |
| stop | `.` | `kill <pid from logs/app.pid>` | 0 |

## Warnings

- Targets were extracted with schema_context_id dbctx-2c246b7230ae (in-one-class/src/main/resources/schema.sql); deployed schema is exactly this file on H2 1.4.197.
- H2 silently rounds values with scale > 2 for DECIMAL(18,2) columns instead of rejecting them.
- The application accepts negative withdrawal amounts (balance check only), which is how precision overflows were reached; this is an app-logic weakness, not part of the extracted predicates.
- Read-back used the H2 web console that the application itself exposes (spring.h2.console.enabled=true) on the permitted port.
- Four targets (pc-d422ab0eead2, dep-6b92cefdf4cd, pc-73e9479cc046, pc-c93d051c414e) were reclassified as INCONCLUSIVE_PRE_PERSISTENCE_FAILURE. Their violations are stopped before persistence but surface as generic HTTP 500 errors.
