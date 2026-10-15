"""Deterministic validation of an agent-produced verification bundle."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

from pydantic import ValidationError

from persispector.persistence.models import PersistenceConstraintReport
from persispector.verification.models import (
    AgentCompletion,
    DeploymentManifest,
    EvidenceReference,
    ValidationIssue,
    ValidationReport,
    VerificationReport,
    VerificationTaskManifest,
)


_RUNTIME_EXERCISED_OUTCOMES = {
    "APPLICATION_REJECTED",
    "APPLICATION_TRANSFORMED",
    "DATABASE_ENFORCED_HANDLED",
    "DATABASE_ENFORCED_UNHANDLED",
    "NO_OBSERVED_ENFORCEMENT",
}


class VerificationEvidenceValidator:
    """Reject missing, inconsistent, or weakly supported agent conclusions."""

    def validate(
        self,
        task: VerificationTaskManifest,
        completion: AgentCompletion | None,
    ) -> ValidationReport:
        issues: list[ValidationIssue] = []
        output_dir = Path(task.output_directory).resolve()
        source_report = PersistenceConstraintReport.model_validate_json(
            Path(task.constraint_report).read_text(encoding="utf-8")
        )
        constraint_ids = {item.finding_id for item in source_report.findings}
        dependency_ids = {
            item.dependency_id
            for model in (source_report.models.orm, source_report.models.db_schema)
            for item in model.dependencies
        }
        known_ids = constraint_ids | dependency_ids

        if completion is None:
            issues.append(
                self._error("missing-completion", "Claude did not return a valid completion object")
            )
            return self._report(task, 0, issues)
        if completion.application != task.application:
            issues.append(
                self._error(
                    "application-mismatch",
                    f"Completion names {completion.application!r}, expected {task.application!r}",
                )
            )

        deployment_path = self._safe_path(
            output_dir, completion.deployment_manifest, issues, "deployment-manifest"
        )
        results_path = self._safe_path(
            output_dir, completion.verification_results, issues, "verification-results"
        )
        deployment = self._load_deployment(deployment_path, issues)
        report = self._load_results(results_path, issues)
        if deployment is None or report is None:
            return self._report(task, 0, issues)

        if deployment.application != task.application:
            issues.append(
                self._error(
                    "deployment-application-mismatch",
                    f"Deployment names {deployment.application!r}, expected {task.application!r}",
                    path=completion.deployment_manifest,
                )
            )
        if report.application != task.application:
            issues.append(
                self._error(
                    "results-application-mismatch",
                    f"Results name {report.application!r}, expected {task.application!r}",
                    path=completion.verification_results,
                )
            )
        if report.constraint_report_schema_version != source_report.schema_version:
            issues.append(
                self._error(
                    "source-schema-mismatch",
                    "Verification results cite a different constraint-report schema version",
                )
            )

        expected = set(task.target_ids)
        if set(report.target_ids) != expected:
            missing = sorted(expected - set(report.target_ids))
            extra = sorted(set(report.target_ids) - expected)
            issues.append(
                self._error(
                    "scope-mismatch",
                    f"Result scope differs from task; missing={missing}, extra={extra}",
                )
            )
        unknown_scope = sorted(set(report.target_ids) - known_ids)
        if unknown_scope:
            issues.append(
                self._error(
                    "unknown-targets",
                    "Unknown target IDs in verification scope: " + ", ".join(unknown_scope),
                )
            )

        case_map = {}
        for case in report.cases:
            if case.case_id in case_map:
                issues.append(
                    self._error(
                        "duplicate-case", f"Duplicate case ID {case.case_id!r}"
                    )
                )
            case_map[case.case_id] = case
            for target_id in case.target_ids:
                if target_id not in expected:
                    issues.append(
                        self._error(
                            "case-unknown-target",
                            f"Case {case.case_id!r} cites out-of-scope target {target_id!r}",
                            target_id=target_id,
                        )
                    )
            if case.purpose in {"control", "violation", "boundary", "read-back"}:
                kinds = {item.kind for item in case.evidence}
                if "http-exchange" not in kinds and case.purpose != "read-back":
                    issues.append(
                        self._error(
                            "case-missing-exchange",
                            f"Case {case.case_id!r} has no saved HTTP exchange",
                        )
                    )
                if case.purpose == "read-back" and "read-back" not in kinds:
                    issues.append(
                        self._error(
                            "readback-case-missing-evidence",
                            f"Read-back case {case.case_id!r} has no read-back evidence",
                        )
                    )
            self._validate_evidence(output_dir, case.evidence, issues)

        result_map = {}
        for result in report.results:
            if result.target_id in result_map:
                issues.append(
                    self._error(
                        "duplicate-result",
                        f"Duplicate result for {result.target_id!r}",
                        target_id=result.target_id,
                    )
                )
            result_map[result.target_id] = result
            expected_kind = (
                "constraint"
                if result.target_id in constraint_ids
                else "dependency"
                if result.target_id in dependency_ids
                else None
            )
            if expected_kind is None:
                issues.append(
                    self._error(
                        "result-unknown-target",
                        f"Unknown result target {result.target_id!r}",
                        target_id=result.target_id,
                    )
                )
            elif result.target_kind != expected_kind:
                issues.append(
                    self._error(
                        "target-kind-mismatch",
                        f"{result.target_id!r} is a {expected_kind}, not {result.target_kind}",
                        target_id=result.target_id,
                    )
                )
            missing_cases = sorted(set(result.case_ids) - set(case_map))
            if missing_cases:
                issues.append(
                    self._error(
                        "missing-cases",
                        f"Result cites unknown cases: {missing_cases}",
                        target_id=result.target_id,
                    )
                )
            self._validate_evidence(output_dir, result.evidence, issues)
            self._validate_support(result, case_map, issues)

        missing_results = sorted(expected - set(result_map))
        extra_results = sorted(set(result_map) - expected)
        if missing_results:
            issues.append(
                self._error(
                    "missing-results",
                    "Targets without a verification result: " + ", ".join(missing_results),
                )
            )
        if extra_results:
            issues.append(
                self._error(
                    "extra-results",
                    "Out-of-scope verification results: " + ", ".join(extra_results),
                )
            )

        expected_coverage = self.coverage_status(report)
        if completion.coverage_status != expected_coverage:
            issues.append(
                self._error(
                    "coverage-status-mismatch",
                    "Completion reports coverage_status="
                    f"{completion.coverage_status!r}, but result outcomes imply "
                    f"{expected_coverage!r}",
                )
            )

        self._validate_evidence(output_dir, deployment.patches, issues)
        self._validate_evidence(output_dir, deployment.logs, issues)
        if completion.execution_status == "complete" and not deployment.cleanup_performed:
            issues.append(
                self._error(
                    "cleanup-not-performed",
                    "A complete run must report that all started processes were cleaned up",
                    path=completion.deployment_manifest,
                )
            )
        if source_report.models.db_schema.contexts and not deployment.schema_context_id:
            issues.append(
                ValidationIssue(
                    severity="warning",
                    code="schema-context-unrecorded",
                    message="The analysis has database variants but deployment.json does not identify one",
                    path=completion.deployment_manifest,
                )
            )
        return self._report(task, len(report.results), issues)

    @staticmethod
    def coverage_status(report: VerificationReport) -> str:
        """Derive runtime coverage independently from predicate accuracy."""

        if not report.results:
            return "none"
        exercised = sum(
            item.outcome in _RUNTIME_EXERCISED_OUTCOMES for item in report.results
        )
        if exercised == len(report.results):
            return "complete"
        if exercised:
            return "partial"
        return "none"

    @staticmethod
    def feedback(report: ValidationReport) -> str:
        errors = [issue for issue in report.issues if issue.severity == "error"]
        warnings = [issue for issue in report.issues if issue.severity == "warning"]
        lines = [
            "The deterministic evidence validator rejected the current bundle.",
            "Correct every error and then rewrite the complete deployment and results files.",
            "Do not drop already valid targets or evidence.",
            "",
            "Errors:",
        ]
        lines.extend(f"- [{item.code}] {item.message}" for item in errors)
        if warnings:
            lines.extend(["", "Warnings to review:"])
            lines.extend(f"- [{item.code}] {item.message}" for item in warnings)
        return "\n".join(lines)

    def _validate_support(self, result, case_map, issues: list[ValidationIssue]) -> None:
        evidence = list(result.evidence)
        for case_id in result.case_ids:
            case = case_map.get(case_id)
            if case is not None:
                evidence.extend(case.evidence)
        kinds = {item.kind for item in evidence}
        if result.exact_predicate_confirmed and "http-exchange" not in kinds:
            issues.append(
                self._error(
                    "confirmed-without-exchange",
                    "A runtime-confirmed predicate needs a saved HTTP exchange",
                    target_id=result.target_id,
                )
            )
        if result.outcome == "APPLICATION_TRANSFORMED" and "read-back" not in kinds:
            issues.append(
                self._error(
                    "transformation-without-readback",
                    "Application transformation requires read-back evidence",
                    target_id=result.target_id,
                )
            )
        if result.outcome.startswith("DATABASE_ENFORCED") and not kinds.intersection(
            {"application-log", "database-log", "sql-trace"}
        ):
            issues.append(
                self._error(
                    "database-outcome-without-database-evidence",
                    "Database enforcement requires a database exception, log, or SQL trace",
                    target_id=result.target_id,
                )
            )
        if result.outcome == "NO_OBSERVED_ENFORCEMENT" and not kinds.intersection(
            {"read-back", "sql-trace"}
        ):
            issues.append(
                self._error(
                    "no-enforcement-without-persistence-observation",
                    "No observed enforcement requires read-back or SQL-trace evidence",
                    target_id=result.target_id,
                )
            )

    def _validate_evidence(
        self,
        output_dir: Path,
        evidence: list[EvidenceReference],
        issues: list[ValidationIssue],
    ) -> None:
        for item in evidence:
            path = self._safe_path(output_dir, item.path, issues, "evidence")
            if path is None or not path.is_file():
                if path is not None:
                    issues.append(
                        self._error(
                            "missing-evidence",
                            f"Evidence file does not exist: {item.path}",
                            path=item.path,
                        )
                    )
                continue
            if item.sha256:
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != item.sha256:
                    issues.append(
                        self._error(
                            "evidence-hash-mismatch",
                            f"Evidence hash differs for {item.path}",
                            path=item.path,
                        )
                    )

    @staticmethod
    def _safe_path(
        output_dir: Path,
        relative: str,
        issues: list[ValidationIssue],
        role: str,
    ) -> Path | None:
        raw = Path(relative)
        if raw.is_absolute():
            issues.append(
                VerificationEvidenceValidator._error(
                    "absolute-output-path",
                    f"{role} path must be relative to the output directory: {relative}",
                    path=relative,
                )
            )
            return None
        candidate = (output_dir / raw).resolve()
        try:
            candidate.relative_to(output_dir)
        except ValueError:
            issues.append(
                VerificationEvidenceValidator._error(
                    "output-path-escape",
                    f"{role} path escapes the output directory: {relative}",
                    path=relative,
                )
            )
            return None
        return candidate

    @staticmethod
    def _load_deployment(
        path: Path | None, issues: list[ValidationIssue]
    ) -> DeploymentManifest | None:
        if path is None or not path.is_file():
            issues.append(
                VerificationEvidenceValidator._error(
                    "missing-deployment-manifest", "deployment.json is missing"
                )
            )
            return None
        try:
            return DeploymentManifest.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as error:
            issues.append(
                VerificationEvidenceValidator._error(
                    "invalid-deployment-manifest", str(error), path=str(path)
                )
            )
            return None

    @staticmethod
    def _load_results(
        path: Path | None, issues: list[ValidationIssue]
    ) -> VerificationReport | None:
        if path is None or not path.is_file():
            issues.append(
                VerificationEvidenceValidator._error(
                    "missing-verification-results", "verification-results.json is missing"
                )
            )
            return None
        try:
            return VerificationReport.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as error:
            issues.append(
                VerificationEvidenceValidator._error(
                    "invalid-verification-results", str(error), path=str(path)
                )
            )
            return None

    @staticmethod
    def _report(
        task: VerificationTaskManifest,
        result_count: int,
        issues: list[ValidationIssue],
    ) -> ValidationReport:
        return ValidationReport(
            valid=not any(issue.severity == "error" for issue in issues),
            checked_at=datetime.now(timezone.utc),
            target_count=len(task.target_ids),
            result_count=result_count,
            issues=issues,
        )

    @staticmethod
    def _error(
        code: str,
        message: str,
        *,
        target_id: str | None = None,
        path: str | None = None,
    ) -> ValidationIssue:
        return ValidationIssue(
            severity="error",
            code=code,
            message=message,
            target_id=target_id,
            path=path,
        )
