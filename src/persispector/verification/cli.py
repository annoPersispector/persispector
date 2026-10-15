"""CLI for delegating one application's runtime verification to Claude Code."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from persispector.verification.claude import ClaudeCodeBackend
from persispector.verification.models import (
    VerificationExecution,
    VerificationPolicy,
)
from persispector.verification.orchestration import VerificationSupervisor
from persispector.verification.task import (
    DEFAULT_ISOLATION_ROOT,
    VerificationTaskBuilder,
)
from persispector.verification.validation import VerificationEvidenceValidator


app = typer.Typer(
    add_completion=False,
    help="Delegate runtime verification of one application to Claude Code.",
)


@app.command("prepare")
def prepare_task(
    project: Annotated[Path, typer.Argument(help="Application project root.")],
    report: Annotated[Path, typer.Argument(help="Persispector constraint-report JSON.")],
    application: Annotated[str | None, typer.Option(help="Application label.")] = None,
    taint_report: Annotated[Path | None, typer.Option(help="Optional CodeQL taint JSON.")] = None,
    isolation_root: Annotated[
        Path, typer.Option(help="Parent directory for isolated agent tasks.")
    ] = DEFAULT_ISOLATION_ROOT,
    task_directory: Annotated[
        Path | None, typer.Option(help="Exact new task directory, overriding the generated path.")
    ] = None,
    target_id: Annotated[
        list[str] | None, typer.Option("--target-id", help="Verify only this target; repeatable.")
    ] = None,
    allowed_host: Annotated[
        list[str] | None, typer.Option("--allowed-host", help="Permitted runtime host; repeatable.")
    ] = None,
    allowed_port: Annotated[
        list[int] | None, typer.Option("--allowed-port", help="Permitted local port; repeatable.")
    ] = None,
    allow_dependency_downloads: Annotated[
        bool, typer.Option(help="Permit dependency downloads during deployment.")
    ] = False,
    allow_external_services: Annotated[
        bool, typer.Option(help="Permit explicitly allowlisted non-local services.")
    ] = False,
    max_runtime: Annotated[
        int, typer.Option(help="Maximum Claude/deployment runtime in seconds.")
    ] = 7_200,
    max_turns: Annotated[int, typer.Option(help="Maximum Claude agent turns.")] = 200,
    max_budget_usd: Annotated[
        float | None, typer.Option(help="Optional Claude API cost ceiling.")
    ] = None,
) -> None:
    """Create an isolated task without invoking Claude Code."""

    policy = VerificationPolicy(
        allowed_hosts=allowed_host or ["127.0.0.1", "localhost"],
        allowed_ports=allowed_port or [],
        allow_dependency_downloads=allow_dependency_downloads,
        allow_external_services=allow_external_services,
        max_runtime_seconds=max_runtime,
        max_agent_turns=max_turns,
        max_budget_usd=max_budget_usd,
    )
    task = VerificationTaskBuilder(isolation_root=isolation_root).build(
        project,
        report,
        application=application,
        taint_report=taint_report,
        target_ids=target_id,
        policy=policy,
        task_directory=task_directory,
    )
    typer.echo(task.task_directory)


@app.command("run")
def run_prepared(
    task_directory: Annotated[Path, typer.Argument(help="Prepared verification task directory.")],
    claude_command: Annotated[str, typer.Option(help="Claude Code executable.")] = "claude",
    model: Annotated[str | None, typer.Option(help="Optional Claude model name.")] = None,
    max_runtime: Annotated[int | None, typer.Option(help="Override runtime limit.")] = None,
    max_turns: Annotated[int | None, typer.Option(help="Override turn limit.")] = None,
    max_budget_usd: Annotated[
        float | None, typer.Option(help="Optional budget for this invocation.")
    ] = None,
    max_validation_resumes: Annotated[
        int, typer.Option(help="Automatic repair turns after evidence validation failures.")
    ] = 2,
) -> None:
    """Start Claude Code for a task previously created by ``prepare``."""

    task = VerificationTaskBuilder.load(task_directory)
    state = ClaudeCodeBackend.load_state(task)
    if state.runs:
        raise typer.BadParameter(
            "This task already has a Claude session; use `persispector-verify resume`"
        )
    backend = ClaudeCodeBackend(
        command=claude_command,
        model=model,
        timeout_seconds=max_runtime,
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
    )
    execution = VerificationSupervisor(
        backend, max_validation_resumes=max_validation_resumes
    ).execute(task)
    _print_execution(execution)
    _finish(execution)


@app.command("delegate")
def delegate(
    project: Annotated[Path, typer.Argument(help="Application project root.")],
    report: Annotated[Path, typer.Argument(help="Persispector constraint-report JSON.")],
    application: Annotated[str | None, typer.Option(help="Application label.")] = None,
    taint_report: Annotated[Path | None, typer.Option(help="Optional CodeQL taint JSON.")] = None,
    isolation_root: Annotated[
        Path, typer.Option(help="Parent directory for isolated agent tasks.")
    ] = DEFAULT_ISOLATION_ROOT,
    task_directory: Annotated[Path | None, typer.Option(help="Exact new task directory.")] = None,
    target_id: Annotated[
        list[str] | None, typer.Option("--target-id", help="Verify only this target; repeatable.")
    ] = None,
    allowed_host: Annotated[
        list[str] | None, typer.Option("--allowed-host", help="Permitted runtime host; repeatable.")
    ] = None,
    allowed_port: Annotated[
        list[int] | None, typer.Option("--allowed-port", help="Permitted local port; repeatable.")
    ] = None,
    allow_dependency_downloads: Annotated[
        bool, typer.Option(help="Permit dependency downloads during deployment.")
    ] = False,
    allow_external_services: Annotated[
        bool, typer.Option(help="Permit explicitly allowlisted non-local services.")
    ] = False,
    claude_command: Annotated[str, typer.Option(help="Claude Code executable.")] = "claude",
    model: Annotated[str | None, typer.Option(help="Optional Claude model name.")] = None,
    max_runtime: Annotated[int, typer.Option(help="Maximum runtime in seconds.")] = 7_200,
    max_turns: Annotated[int, typer.Option(help="Maximum Claude agent turns.")] = 200,
    max_budget_usd: Annotated[
        float | None, typer.Option(help="Optional Claude API cost ceiling.")
    ] = None,
    max_validation_resumes: Annotated[
        int, typer.Option(help="Automatic repair turns after evidence validation failures.")
    ] = 2,
) -> None:
    """Prepare, delegate, validate, repair, and render one application."""

    policy = VerificationPolicy(
        allowed_hosts=allowed_host or ["127.0.0.1", "localhost"],
        allowed_ports=allowed_port or [],
        allow_dependency_downloads=allow_dependency_downloads,
        allow_external_services=allow_external_services,
        max_runtime_seconds=max_runtime,
        max_agent_turns=max_turns,
        max_budget_usd=max_budget_usd,
    )
    task = VerificationTaskBuilder(isolation_root=isolation_root).build(
        project,
        report,
        application=application,
        taint_report=taint_report,
        target_ids=target_id,
        policy=policy,
        task_directory=task_directory,
    )
    backend = ClaudeCodeBackend(
        command=claude_command,
        model=model,
        timeout_seconds=max_runtime,
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
    )
    execution = VerificationSupervisor(
        backend, max_validation_resumes=max_validation_resumes
    ).execute(task)
    _print_execution(execution)
    _finish(execution)


@app.command("resume")
def resume(
    task_directory: Annotated[Path, typer.Argument(help="Existing verification task directory.")],
    feedback_file: Annotated[
        Path | None, typer.Option(help="Optional additional instructions for this resume turn.")
    ] = None,
    claude_command: Annotated[str, typer.Option(help="Claude Code executable.")] = "claude",
    model: Annotated[str | None, typer.Option(help="Optional Claude model name.")] = None,
    max_runtime: Annotated[int | None, typer.Option(help="Override runtime limit.")] = None,
    max_turns: Annotated[int | None, typer.Option(help="Override turn limit.")] = None,
    max_budget_usd: Annotated[
        float | None, typer.Option(help="Optional budget for this invocation.")
    ] = None,
    max_validation_resumes: Annotated[
        int, typer.Option(help="Additional automatic evidence-repair turns.")
    ] = 1,
) -> None:
    """Resume a paused, blocked, or incomplete Claude Code session."""

    task = VerificationTaskBuilder.load(task_directory)
    feedback = (
        feedback_file.read_text(encoding="utf-8") if feedback_file is not None else None
    )
    backend = ClaudeCodeBackend(
        command=claude_command,
        model=model,
        timeout_seconds=max_runtime,
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
    )
    execution = VerificationSupervisor(
        backend, max_validation_resumes=max_validation_resumes
    ).resume(task, feedback=feedback)
    _print_execution(execution)
    _finish(execution)


@app.command("validate")
def validate(
    task_directory: Annotated[Path, typer.Argument(help="Existing verification task directory.")],
) -> None:
    """Validate the latest Claude output without invoking the agent."""

    task = VerificationTaskBuilder.load(task_directory)
    state = ClaudeCodeBackend.load_state(task)
    completion = state.runs[-1].completion if state.runs else None
    report = VerificationEvidenceValidator().validate(task, completion)
    path = Path(task.supervisor_directory) / "validation.json"
    path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    typer.echo(path)
    for issue in report.issues:
        typer.echo(f"{issue.severity}: [{issue.code}] {issue.message}")
    if not report.valid:
        raise typer.Exit(code=2)


@app.command("render")
def render(
    task_directory: Annotated[Path, typer.Argument(help="Existing verification task directory.")],
) -> None:
    """Render the latest valid result as Markdown and CSV."""

    task = VerificationTaskBuilder.load(task_directory)
    state = ClaudeCodeBackend.load_state(task)
    if not state.runs or state.runs[-1].completion is None:
        raise typer.BadParameter("The task has no valid Claude completion")
    completion = state.runs[-1].completion
    validation = VerificationEvidenceValidator().validate(task, completion)
    if not validation.valid:
        raise typer.BadParameter(
            "The latest bundle is invalid; run `persispector-verify validate` for details"
        )
    markdown, csv = VerificationSupervisor.render(task, completion)
    typer.echo(markdown)
    typer.echo(csv)


def _print_execution(execution: VerificationExecution) -> None:
    typer.echo(f"task: {execution.task.task_directory}")
    typer.echo(f"execution status: {execution.final_run.execution_status}")
    typer.echo(f"coverage status: {execution.final_run.coverage_status}")
    typer.echo(f"session: {execution.final_run.session_id or 'unavailable'}")
    typer.echo(f"evidence valid: {execution.validation.valid}")
    typer.echo(f"results: {execution.validation.result_count}/{execution.validation.target_count}")
    if execution.final_run.execution_status == "needs-funds":
        typer.echo(
            "Claude reported exhausted credits. Add funds, then run: "
            f"persispector-verify resume {execution.task.task_directory}"
        )
    if execution.final_run.execution_status == "rate-limited":
        typer.echo(
            "Claude reported a temporary session or usage limit. Wait for the "
            "reported reset, then run: "
            f"persispector-verify resume {execution.task.task_directory}"
        )


def _finish(execution: VerificationExecution) -> None:
    execution_status = execution.final_run.execution_status
    if execution_status in {"needs-funds", "rate-limited"}:
        raise typer.Exit(code=75)
    if not execution.validation.valid:
        raise typer.Exit(code=2)
    if execution_status != "complete":
        raise typer.Exit(code=1)
    # Preserve the v1 command behavior: incomplete coverage still returns 1,
    # even though execution itself is now correctly reported as complete.
    if execution.final_run.coverage_status != "complete":
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
