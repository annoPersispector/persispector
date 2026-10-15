"""Human- and spreadsheet-readable runtime-verification reports."""

from __future__ import annotations

import csv
import io

from persispector.persistence.models import PersistenceConstraintReport
from persispector.verification.models import DeploymentManifest, VerificationReport
from persispector.verification.validation import VerificationEvidenceValidator


def render_verification_markdown(
    report: VerificationReport,
    deployment: DeploymentManifest,
    source: PersistenceConstraintReport,
) -> str:
    targets = _target_metadata(source)
    outcomes: dict[str, int] = {}
    confirmed = 0
    for item in report.results:
        outcomes[item.outcome] = outcomes.get(item.outcome, 0) + 1
        confirmed += int(item.exact_predicate_confirmed)
    lines = [
        f"# Runtime persistence verification: {report.application}",
        "",
        "## Summary",
        "",
        f"- Targets: {len(report.target_ids)}",
        f"- Results: {len(report.results)}",
        f"- Runtime coverage: {VerificationEvidenceValidator.coverage_status(report)}",
        f"- Exact predicates confirmed: {confirmed}",
        f"- Runtime database: {deployment.runtime_database or 'not recorded'}",
        f"- Schema context: {deployment.schema_context_id or 'not recorded'}",
        f"- Cleanup performed: {'yes' if deployment.cleanup_performed else 'no'}",
        "",
        "| Outcome | Count |",
        "| --- | ---: |",
    ]
    lines.extend(f"| `{name}` | {count} |" for name, count in sorted(outcomes.items()))
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Target | Declaration | Outcome | Confirmed | Enforcement | App implementation | Response handling | Confidence | Cases | Rationale |",
            "| --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for item in report.results:
        meta = targets.get(item.target_id, {})
        declaration = meta.get("declaration", "unknown")
        cases = ", ".join(f"`{value}`" for value in item.case_ids) or "—"
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{_md(item.target_id)}`",
                    _md(declaration),
                    f"`{item.outcome}`",
                    "yes" if item.exact_predicate_confirmed else "no",
                    item.observed_enforcement,
                    (
                        "yes"
                        if item.application_layer_implemented is True
                        else "no"
                        if item.application_layer_implemented is False
                        else "not assessed"
                    ),
                    item.response_handling,
                    f"{item.confidence:.2f}",
                    cases,
                    _md(item.rationale),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Deployment", ""])
    if deployment.base_urls:
        lines.append("- Base URLs: " + ", ".join(f"`{value}`" for value in deployment.base_urls))
    if deployment.commands:
        lines.extend(
            [
                "",
                "| Purpose | Working directory | Command | Exit |",
                "| --- | --- | --- | ---: |",
            ]
        )
        for command in deployment.commands:
            lines.append(
                f"| {_md(command.purpose)} | `{_md(command.working_directory)}` | "
                f"`{_md(command.command)}` | {command.exit_code if command.exit_code is not None else '—'} |"
            )
    if report.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {_md(value)}" for value in report.warnings)
    return "\n".join(lines).rstrip() + "\n"


def render_verification_csv(
    report: VerificationReport,
    source: PersistenceConstraintReport,
) -> str:
    targets = _target_metadata(source)
    stream = io.StringIO()
    fields = [
        "application",
        "target_id",
        "target_kind",
        "declaration",
        "layer",
        "subject",
        "source_locations",
        "outcome",
        "exact_predicate_confirmed",
        "observed_enforcement",
        "application_layer_implemented",
        "response_handling",
        "confidence",
        "case_ids",
        "evidence_files",
        "rationale",
        "limitations",
    ]
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for item in report.results:
        meta = targets.get(item.target_id, {})
        writer.writerow(
            {
                "application": report.application,
                "target_id": item.target_id,
                "target_kind": item.target_kind,
                "declaration": meta.get("declaration", ""),
                "layer": meta.get("layer", ""),
                "subject": meta.get("subject", ""),
                "source_locations": meta.get("sources", ""),
                "outcome": item.outcome,
                "exact_predicate_confirmed": item.exact_predicate_confirmed,
                "observed_enforcement": item.observed_enforcement,
                "application_layer_implemented": item.application_layer_implemented,
                "response_handling": item.response_handling,
                "confidence": f"{item.confidence:.3f}",
                "case_ids": ";".join(item.case_ids),
                "evidence_files": ";".join(value.path for value in item.evidence),
                "rationale": item.rationale,
                "limitations": ";".join(item.limitations),
            }
        )
    return stream.getvalue()


def _target_metadata(source: PersistenceConstraintReport) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for item in source.findings:
        subject = item.subject
        owner = subject.table or subject.entity or "unknown"
        members = subject.columns or subject.fields
        result[item.finding_id] = {
            "declaration": f"{item.kind}: {item.predicate}",
            "layer": item.layer,
            "subject": owner + (f"({', '.join(members)})" if members else ""),
            "sources": ";".join(
                f"{value.file_path}:{value.start_line or ''}" for value in item.sources
            ),
        }
    for model in (source.models.orm, source.models.db_schema):
        for item in model.dependencies:
            result[item.dependency_id] = {
                "declaration": f"{item.kind}: {item.source.name or 'unknown'} -> {item.target.name or 'unknown'}",
                "layer": item.layer,
                "subject": item.source.name or "unknown",
                "sources": ";".join(
                    f"{value.file_path}:{value.start_line or ''}" for value in item.sources
                ),
            }
    return result


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
