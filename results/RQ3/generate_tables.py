#!/usr/bin/env python3
"""Regenerate the RQ3 accuracy table from the manual-review workbook."""

from __future__ import annotations

from pathlib import Path

from openpyxl import load_workbook


ROOT = Path(__file__).resolve().parent


def markdown(headers: list[str], rows: list[list[object]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(map(str, row)) + " |" for row in rows)
    return "\n".join(lines)


def reviewed_status(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and float(value) in {0.0, 1.0}:
        return float(value) == 1.0
    return None


def main() -> None:
    workbook = load_workbook(
        ROOT / "persispector_corpus_10.xlsx", read_only=False, data_only=True
    )
    findings: list[dict[str, object]] = []
    for sheet in workbook.worksheets:
        headers = [cell.value for cell in sheet[1]]
        index = {name: position for position, name in enumerate(headers)}
        for values in sheet.iter_rows(min_row=2, values_only=True):
            if not values[index["target_id"]]:
                continue
            findings.append({name: values[position] for name, position in index.items()})
    workbook.close()

    direct_llm = [row for row in findings if row["origin"] == "llm"]
    missing_review = [
        row["target_id"]
        for row in direct_llm
        if reviewed_status(row["manual_review_status"]) is None
    ]
    if missing_review:
        raise SystemExit(
            "Missing manual decisions for LLM findings: " + ", ".join(map(str, missing_review))
        )

    # Four join-table dependences are derived from the same two source declarations
    # as the four reviewed LLM foreign-key constraints, so the paper attributes them
    # to the LLM-assisted component as well.
    llm_fk_sources = {
        row["source_locations"]
        for row in direct_llm
        if row["declaration_kind"] == "foreign-key"
        and reviewed_status(row["manual_review_status"])
    }
    derived_llm_dependences = [
        row
        for row in findings
        if row["target_kind"] == "dependency"
        and row["declaration_kind"] == "foreign-key"
        and row["source_locations"] in llm_fk_sources
    ]

    llm_reported = len(direct_llm) + len(derived_llm_dependences)
    llm_correct = sum(
        reviewed_status(row["manual_review_status"]) is True for row in direct_llm
    ) + len(derived_llm_dependences)
    llm_incorrect = llm_reported - llm_correct

    deterministic_reported = len(findings) - llm_reported
    deterministic_correct = deterministic_reported
    deterministic_incorrect = 0
    overall_reported = len(findings)
    overall_correct = deterministic_correct + llm_correct
    overall_incorrect = deterministic_incorrect + llm_incorrect

    def precision(correct: int, reported: int) -> str:
        return f"{100 * correct / reported:.1f}%"

    table = [
        [
            "Deterministic static analysis",
            deterministic_reported,
            deterministic_correct,
            deterministic_incorrect,
            precision(deterministic_correct, deterministic_reported),
        ],
        [
            "LLM-assisted analysis",
            llm_reported,
            llm_correct,
            llm_incorrect,
            precision(llm_correct, llm_reported),
        ],
        [
            "Overall",
            overall_reported,
            overall_correct,
            overall_incorrect,
            precision(overall_correct, overall_reported),
        ],
    ]
    print("Table 6. Finding-level accuracy by analysis component.\n")
    print(markdown(["Component", "Reported", "Correct", "Incorrect", "Precision"], table))


if __name__ == "__main__":
    main()
