#!/usr/bin/env python3
"""Regenerate the RQ1 tables from stored runtime-verification results."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APPLICATIONS = [
    ("Baeldung_spring-security-registration", "Baeldung Security Registration"),
    ("apache_seatunnel-web", "Apache SeaTunnel Web"),
    ("ddd-by-examples_all-things-cqrs__in-one-class", "All Things CQRS"),
    ("eclipse-jifa_jifa", "Eclipse Jifa"),
    (
        "eventuate-tram_eventuate-tram-examples-customers-and-orders",
        "Eventuate Customers and Orders",
    ),
    ("funtl_MyShopPlus", "MyShopPlus"),
    ("gothinkster_spring-boot-realworld-example-app", "Spring Boot RealWorld"),
    ("spinnaker_kayenta", "Spinnaker Kayenta"),
    ("vipshop_Saturn", "Vipshop Saturn"),
    ("yanagishima_yanagishima", "Yanagishima"),
]
KINDS = [
    ("length", "Length"),
    ("type", "Type"),
    ("not-null", "Not-null"),
    ("composite-unique", "Composite unique"),
    ("precision-scale", "Precision/scale"),
    ("primary-key", "Primary key"),
    ("unique", "Unique"),
]
DATABASE_OUTCOMES = {
    "DATABASE_ENFORCED_HANDLED",
    "DATABASE_ENFORCED_UNHANDLED",
}


def markdown(headers: list[str], rows: list[list[object]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(map(str, row)) + " |" for row in rows)
    return "\n".join(lines)


def load_application(application: str) -> tuple[list[dict[str, str]], dict[str, str]]:
    directory = ROOT / application
    result_path = directory / "output" / "verification-results.csv"
    constraint_path = directory / "inputs" / "persistence-constraints.json"
    if not result_path.is_file():
        raise SystemExit(f"Missing runtime results: {result_path}")
    if not constraint_path.is_file():
        raise SystemExit(f"Missing static finding metadata: {constraint_path}")

    with result_path.open(encoding="utf-8-sig", newline="") as handle:
        results = list(csv.DictReader(handle))
    with constraint_path.open(encoding="utf-8") as handle:
        report = json.load(handle)
    kinds = {
        finding["finding_id"]: finding["kind"]
        for finding in report["findings"]
    }
    return results, kinds


def main() -> None:
    exact_confirmed = 0
    by_application: Counter[str] = Counter()
    by_kind: Counter[str] = Counter()

    for application, _ in APPLICATIONS:
        results, kinds = load_application(application)
        exact_confirmed += sum(
            row["exact_predicate_confirmed"].lower() == "true"
            for row in results
        )
        for row in results:
            if not (
                row["target_kind"] == "constraint"
                and row["exact_predicate_confirmed"].lower() == "true"
                and row["outcome"] in DATABASE_OUTCOMES
            ):
                continue
            target_id = row["target_id"]
            if target_id not in kinds:
                raise SystemExit(
                    f"Constraint {target_id} is absent from "
                    f"{application}/inputs/persistence-constraints.json"
                )
            by_application[application] += 1
            by_kind[kinds[target_id]] += 1

    total = sum(by_application.values())
    table_2 = [
        [label, by_application[application]]
        for application, label in APPLICATIONS
    ]
    table_2.append(["Total", total])

    table_3 = [[label, by_kind[kind]] for kind, label in KINDS]
    table_3.append(["Total", total])

    print(f"Exact predicates confirmed: {exact_confirmed}")
    print(f"Confirmed constraints not enforced in application code: {total}")
    print("\nTable 2. Confirmed findings not enforced by application code, by application.\n")
    print(markdown(["Application", "Findings"], table_2))
    print("\nTable 3. Confirmed findings not enforced by application code, by constraint kind.\n")
    print(markdown(["Constraint kind", "Findings"], table_3))


if __name__ == "__main__":
    main()
