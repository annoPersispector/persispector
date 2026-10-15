"""Supervise a Claude Code verification run and evidence-repair turns."""

from __future__ import annotations

from pathlib import Path

from persispector.persistence.models import PersistenceConstraintReport
from persispector.verification.claude import ClaudeCodeBackend
from persispector.verification.models import (
    AgentCompletion,
    DeploymentManifest,
    ValidationReport,
    VerificationExecution,
    VerificationReport,
    VerificationTaskManifest,
)
from persispector.verification.render import (
    render_verification_csv,
    render_verification_markdown,
)
from persispector.verification.validation import VerificationEvidenceValidator


_NON_RESUMABLE_WITHOUT_USER = {
    "needs-approval",
    "needs-credentials",
    "needs-funds",
    "rate-limited",
    "blocked",
    "timed-out",
}


class VerificationSupervisor:
    """Run one application agent and resume it only for concrete validation defects."""

    def __init__(
        self,
        backend: ClaudeCodeBackend,
        *,
        validator: VerificationEvidenceValidator | None = None,
        max_validation_resumes: int = 2,
    ) -> None:
        self.backend = backend
        self.validator = validator or VerificationEvidenceValidator()
        self.max_validation_resumes = max_validation_resumes

    def execute(self, task: VerificationTaskManifest) -> VerificationExecution:
        run = self.backend.start(task)
        validation = self._validate_and_save(task, run.completion)
        resumes = 0
        while (
            not validation.valid
            and resumes < self.max_validation_resumes
            and run.execution_status not in _NON_RESUMABLE_WITHOUT_USER
            and run.session_id is not None
        ):
            run = self.backend.resume(
                task,
                run.session_id,
                self.validator.feedback(validation),
            )
            resumes += 1
            validation = self._validate_and_save(task, run.completion)
        execution = VerificationExecution(
            task=task,
            final_run=run,
            validation=validation,
            resume_count=resumes,
        )
        self._write_execution(task, execution)
        if validation.valid and run.completion is not None:
            self.render(task, run.completion)
        return execution

    def resume(
        self,
        task: VerificationTaskManifest,
        *,
        feedback: str | None = None,
    ) -> VerificationExecution:
        state = self.backend.load_state(task)
        if not state.runs:
            raise ValueError("This task has no Claude Code session to resume")
        prior = state.runs[-1]
        if not prior.session_id:
            raise ValueError("The last Claude Code run did not return a session ID")
        validation = self._validate_and_save(task, prior.completion)
        message = feedback or (
            self.validator.feedback(validation)
            if not validation.valid
            else (
                "Continue the verification assignment from the existing valid partial "
                "bundle. Resolve the previously reported blockers where possible, preserve "
                "all valid evidence, and rewrite the complete result bundle."
            )
        )
        run = self.backend.resume(task, prior.session_id, message)
        validation = self._validate_and_save(task, run.completion)
        resumes = 1
        while (
            not validation.valid
            and resumes < self.max_validation_resumes
            and run.execution_status not in _NON_RESUMABLE_WITHOUT_USER
            and run.session_id is not None
        ):
            run = self.backend.resume(
                task, run.session_id, self.validator.feedback(validation)
            )
            resumes += 1
            validation = self._validate_and_save(task, run.completion)
        execution = VerificationExecution(
            task=task,
            final_run=run,
            validation=validation,
            resume_count=resumes,
        )
        self._write_execution(task, execution)
        if validation.valid and run.completion is not None:
            self.render(task, run.completion)
        return execution

    def validate_latest(self, task: VerificationTaskManifest) -> ValidationReport:
        state = self.backend.load_state(task)
        completion = state.runs[-1].completion if state.runs else None
        return self._validate_and_save(task, completion)

    @staticmethod
    def render(
        task: VerificationTaskManifest,
        completion: AgentCompletion,
    ) -> tuple[Path, Path]:
        output = Path(task.output_directory)
        deployment = DeploymentManifest.model_validate_json(
            VerificationSupervisor._result_path(
                output, completion.deployment_manifest
            ).read_text(
                encoding="utf-8"
            )
        )
        report = VerificationReport.model_validate_json(
            VerificationSupervisor._result_path(
                output, completion.verification_results
            ).read_text(
                encoding="utf-8"
            )
        )
        source = PersistenceConstraintReport.model_validate_json(
            Path(task.constraint_report).read_text(encoding="utf-8")
        )
        markdown = output / "verification-report.md"
        csv = output / "verification-results.csv"
        markdown.write_text(
            render_verification_markdown(report, deployment, source), encoding="utf-8"
        )
        csv.write_text(render_verification_csv(report, source), encoding="utf-8")
        return markdown, csv

    def _validate_and_save(
        self,
        task: VerificationTaskManifest,
        completion: AgentCompletion | None,
    ) -> ValidationReport:
        result = self.validator.validate(task, completion)
        path = Path(task.supervisor_directory) / "validation.json"
        path.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return result

    @staticmethod
    def _write_execution(
        task: VerificationTaskManifest, execution: VerificationExecution
    ) -> None:
        path = Path(task.supervisor_directory) / "execution.json"
        path.write_text(execution.model_dump_json(indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _result_path(output: Path, relative: str) -> Path:
        candidate = (output / relative).resolve()
        try:
            candidate.relative_to(output.resolve())
        except ValueError as error:
            raise ValueError(f"Result path escapes output directory: {relative}") from error
        return candidate
