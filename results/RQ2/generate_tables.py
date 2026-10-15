#!/usr/bin/env python3
"""Regenerate the RQ2 tables from the reviewed finding inventory."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APPLICATIONS = [
    ("Baeldung_spring-security-registration", "Baeldung Registration"),
    ("apache_seatunnel-web", "SeaTunnel Web"),
    ("ddd-by-examples_all-things-cqrs__in-one-class", "All Things CQRS"),
    ("eclipse-jifa_jifa", "Eclipse Jifa"),
    (
        "eventuate-tram_eventuate-tram-examples-customers-and-orders",
        "Eventuate",
    ),
    ("funtl_MyShopPlus", "MyShopPlus"),
    ("gothinkster_spring-boot-realworld-example-app", "RealWorld"),
    ("spinnaker_kayenta", "Kayenta"),
    ("vipshop_Saturn", "Saturn"),
    ("yanagishima_yanagishima", "Yanagishima"),
]
CONSTRAINT_KINDS = [
    ("type", "Type"),
    ("not-null", "Not-null"),
    ("length", "Length"),
    ("primary-key", "Primary key"),
    ("precision-scale", "Precision/scale"),
    ("unique", "Unique"),
    ("composite-unique", "Composite unique"),
    ("foreign-key", "Foreign key"),
    ("character-set", "Character-set"),
]
DEPENDENCE_KINDS = [
    ("inheritance", "Inheritance"),
    ("association/composition", "Association/composition"),
    ("foreign-key", "Foreign key"),
]


def markdown(headers: list[str], rows: list[list[object]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(map(str, row)) + " |" for row in rows)
    return "\n".join(lines)


def category(row: dict[str, str]) -> str:
    kind = row["declaration_kind"]
    if row["target_kind"] == "constraint" and kind == "custom":
        return "character-set"
    if row["target_kind"] == "dependency" and kind in {"association", "embedded"}:
        return "association/composition"
    return kind


def main() -> None:
    path = ROOT / "reviewed-findings.csv"
    with path.open(encoding="utf-8", newline="") as handle:
        reported = list(csv.DictReader(handle))

    verified = [row for row in reported if row["review_decision"] != "incorrect"]
    active = [row for row in verified if row["runtime_outcome"] != "VARIANT_NOT_DEPLOYED"]

    per_application = Counter(
        (row["application"], row["target_kind"]) for row in verified
    )
    table_4 = [
        [
            label,
            per_application[application, "constraint"],
            per_application[application, "dependency"],
        ]
        for application, label in APPLICATIONS
    ]
    table_4.append(
        [
            "Total",
            sum(row[1] for row in table_4),
            sum(row[2] for row in table_4),
        ]
    )

    source_counts = Counter((row["target_kind"], category(row)) for row in verified)
    active_counts = Counter((row["target_kind"], category(row)) for row in active)
    table_5: list[list[object]] = [["Constraints", "", ""]]
    table_5.extend(
        [label, source_counts["constraint", kind], active_counts["constraint", kind]]
        for kind, label in CONSTRAINT_KINDS
    )
    table_5.append(
        [
            "Constraint total",
            sum(source_counts["constraint", kind] for kind, _ in CONSTRAINT_KINDS),
            sum(active_counts["constraint", kind] for kind, _ in CONSTRAINT_KINDS),
        ]
    )
    table_5.append(["Dependences", "", ""])
    table_5.extend(
        [label, source_counts["dependency", kind], active_counts["dependency", kind]]
        for kind, label in DEPENDENCE_KINDS
    )
    table_5.append(
        [
            "Dependence total",
            sum(source_counts["dependency", kind] for kind, _ in DEPENDENCE_KINDS),
            sum(active_counts["dependency", kind] for kind, _ in DEPENDENCE_KINDS),
        ]
    )

    print("Table 4. Findings by application.\n")
    print(markdown(["Application", "Constraints", "Dependences"], table_4))
    print("\nTable 5. Findings by type.\n")
    print(markdown(["Kind", "Source", "Active"], table_5))


if __name__ == "__main__":
    main()
