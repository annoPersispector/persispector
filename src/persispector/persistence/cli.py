"""CLI for declared persistence-constraint analysis."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

import typer

from persispector.persistence.analysis import (
    OpenAICompatibleConstraintClient,
    PersistenceConstraintAnalyzer,
)
from persispector.persistence.codeql_flow import (
    CodeQLTaintAnalyzer,
    apply_codeql_taint_analysis,
)
from persispector.persistence.discovery import PersistenceEvidencePreparer
from persispector.persistence.models import (
    CodeQLTaintAnalysis,
    PersistenceConstraintReport,
    PreparedPersistenceEvidence,
)
from persispector.persistence.render import render_persistence_markdown


app = typer.Typer(
    add_completion=False,
    help="Discover and analyze declared persistence constraints.",
)


@app.command("trace")
def trace_taint(
    project: Annotated[Path, typer.Argument(help="Java project root.")],
    evidence: Annotated[Path, typer.Argument(help="Prepared evidence JSON from `prepare`.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="CodeQL reachability/taint JSON.")],
    database_dir: Annotated[Path | None, typer.Option(help="Reusable CodeQL database directory.")] = None,
    work_dir: Annotated[Path | None, typer.Option(help="Directory for temporary CodeQL query files.")] = None,
    codeql_command: Annotated[str | None, typer.Option(help="CodeQL CLI executable; defaults to CODEQL_COMMAND or codeql.")] = None,
    build_mode: Annotated[str, typer.Option(help="CodeQL Java extraction mode: none or autobuild.")] = "none",
    timeout: Annotated[float, typer.Option(help="Timeout in seconds for each CodeQL phase.")] = 1_800,
) -> None:
    """Trace endpoint calls and values to persistence terminals with CodeQL."""

    prepared = PreparedPersistenceEvidence.model_validate_json(
        evidence.read_text(encoding="utf-8")
    )
    project_resolved = project.resolve()
    if project_resolved != Path(prepared.project_path).resolve():
        raise typer.BadParameter(
            "PROJECT does not match the project_path recorded in the evidence file."
        )
    flow = _trace_codeql(
        prepared,
        codeql_command=codeql_command,
        database_dir=database_dir or output.parent / "codeql-db",
        work_dir=work_dir or output.parent / "codeql-work",
        build_mode=build_mode,
        timeout=timeout,
    )
    _write_model(output, flow)
    if flow.failures:
        raise typer.Exit(code=1)


@app.command()
def prepare(
    project: Annotated[Path, typer.Argument(help="Java project or source-module root.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Prepared evidence JSON.")],
    analysis_cache: Annotated[Path | None, typer.Option(help="CLDK analysis cache directory.")] = None,
    eager: Annotated[bool, typer.Option(help="Refresh the CLDK analysis cache.")] = False,
    max_artifact_chars: Annotated[int, typer.Option(help="Maximum characters per evidence artifact.")] = 48_000,
    max_file_chars: Annotated[int, typer.Option(help="Maximum DB-schema-file size in characters.")] = 1_000_000,
    include_tests: Annotated[bool, typer.Option(help="Include src/test Java and resources.")] = False,
    endpoint_max_depth: Annotated[int, typer.Option(help="Deprecated compatibility option; CodeQL now computes reachability.")] = 8,
    endpoint_max_methods: Annotated[int, typer.Option(help="Deprecated compatibility option; CodeQL now computes reachability.")] = 1_000,
) -> None:
    """Collect evidence and deterministic findings without a provider call."""

    prepared = _prepare(
        project,
        analysis_json_path=analysis_cache,
        eager=eager,
        max_artifact_chars=max_artifact_chars,
        max_file_chars=max_file_chars,
        include_tests=include_tests,
        endpoint_max_depth=endpoint_max_depth,
        endpoint_max_methods=endpoint_max_methods,
    )
    _write_model(output, prepared)


@app.command()
def analyze(
    evidence: Annotated[Path, typer.Argument(help="Prepared evidence JSON from `prepare`.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Constraint report JSON.")],
    temperature: Annotated[float, typer.Option(help="Model sampling temperature.")] = 0.0,
    limit: Annotated[int | None, typer.Option(help="Analyze only the first N artifacts.")] = None,
    log_level: Annotated[str, typer.Option(help="Python logging level.")] = "INFO",
    taint_flow: Annotated[Path | None, typer.Option(help="Optional CodeQL taint-flow JSON from `trace`.")] = None,
) -> None:
    """Combine deterministic findings with LLM analysis of residual evidence."""

    _configure_logging(log_level)
    prepared = PreparedPersistenceEvidence.model_validate_json(
        evidence.read_text(encoding="utf-8")
    )
    taint_failures = False
    if taint_flow is not None:
        flow = CodeQLTaintAnalysis.model_validate_json(
            taint_flow.read_text(encoding="utf-8")
        )
        taint_failures = bool(flow.failures)
        prepared = apply_codeql_taint_analysis(
            prepared,
            flow,
        )
    report = _analyze(
        prepared,
        evidence_file=evidence,
        temperature=temperature,
        limit=limit,
    )
    _write_model(output, report)
    if report.failures or taint_failures:
        raise typer.Exit(code=1)


@app.command("render")
def render_report(
    report_file: Annotated[Path, typer.Argument(help="Constraint report JSON from `analyze`.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Markdown report.")],
) -> None:
    """Render an analyzed JSON report as Markdown without model calls."""

    report = PersistenceConstraintReport.model_validate_json(
        report_file.read_text(encoding="utf-8")
    )
    _write_text(output, render_persistence_markdown(report))


@app.command("run")
def run_all(
    project: Annotated[Path, typer.Argument(help="Java project or source-module root.")],
    output_dir: Annotated[Path, typer.Option(help="Directory for all three output artifacts.")],
    analysis_cache: Annotated[Path | None, typer.Option(help="CLDK analysis cache directory.")] = None,
    eager: Annotated[bool, typer.Option(help="Refresh the CLDK analysis cache.")] = False,
    max_artifact_chars: Annotated[int, typer.Option(help="Maximum characters per evidence artifact.")] = 48_000,
    max_file_chars: Annotated[int, typer.Option(help="Maximum DB-schema-file size in characters.")] = 1_000_000,
    include_tests: Annotated[bool, typer.Option(help="Include src/test Java and resources.")] = False,
    endpoint_max_depth: Annotated[int, typer.Option(help="Deprecated compatibility option; CodeQL now computes reachability.")] = 8,
    endpoint_max_methods: Annotated[int, typer.Option(help="Deprecated compatibility option; CodeQL now computes reachability.")] = 1_000,
    temperature: Annotated[float, typer.Option(help="Model sampling temperature.")] = 0.0,
    limit: Annotated[int | None, typer.Option(help="Analyze only the first N artifacts.")] = None,
    log_level: Annotated[str, typer.Option(help="Python logging level.")] = "INFO",
    codeql_taint: Annotated[bool, typer.Option(help="Run CodeQL endpoint reachability and persistence taint flow.")] = False,
    codeql_command: Annotated[str | None, typer.Option(help="CodeQL CLI executable; defaults to CODEQL_COMMAND or codeql.")] = None,
    codeql_database: Annotated[Path | None, typer.Option(help="Reusable CodeQL database directory.")] = None,
    codeql_build_mode: Annotated[str, typer.Option(help="CodeQL Java extraction mode: none or autobuild.")] = "none",
    codeql_timeout: Annotated[float, typer.Option(help="Timeout in seconds for each CodeQL phase.")] = 1_800,
) -> None:
    """Prepare, analyze, and render the standard report artifacts."""

    _configure_logging(log_level)
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = output_dir / "persistence-evidence.json"
    report_path = output_dir / "persistence-constraints.json"
    markdown_path = output_dir / "persistence-report.md"
    taint_path = output_dir / "persistence-taint.json"
    prepared = _prepare(
        project,
        analysis_json_path=analysis_cache,
        eager=eager,
        max_artifact_chars=max_artifact_chars,
        max_file_chars=max_file_chars,
        include_tests=include_tests,
        endpoint_max_depth=endpoint_max_depth,
        endpoint_max_methods=endpoint_max_methods,
    )
    taint_failures = False
    if codeql_taint:
        flow = _trace_codeql(
            prepared,
            codeql_command=codeql_command,
            database_dir=codeql_database or output_dir / "codeql-db",
            work_dir=output_dir / "codeql-work",
            build_mode=codeql_build_mode,
            timeout=codeql_timeout,
        )
        _write_model(taint_path, flow)
        prepared = apply_codeql_taint_analysis(prepared, flow)
        taint_failures = bool(flow.failures)
    _write_model(evidence_path, prepared)
    report = _analyze(
        prepared,
        evidence_file=evidence_path,
        temperature=temperature,
        limit=limit,
    )
    _write_model(report_path, report)
    _write_text(markdown_path, render_persistence_markdown(report))
    if report.failures or taint_failures:
        raise typer.Exit(code=1)


def _prepare(project: Path, **options: object) -> PreparedPersistenceEvidence:
    return PersistenceEvidencePreparer.from_project(project, **options).prepare()


def _trace_codeql(
    prepared: PreparedPersistenceEvidence,
    *,
    codeql_command: str | None,
    database_dir: Path,
    work_dir: Path,
    build_mode: str,
    timeout: float,
) -> CodeQLTaintAnalysis:
    try:
        analyzer = CodeQLTaintAnalyzer(
            codeql_command=codeql_command,
            database_dir=database_dir,
            work_dir=work_dir,
            build_mode=build_mode,
            timeout_seconds=timeout,
        )
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    return analyzer.analyze(prepared)


def _analyze(
    prepared: PreparedPersistenceEvidence,
    *,
    evidence_file: Path,
    temperature: float,
    limit: int | None,
) -> PersistenceConstraintReport:
    client = OpenAICompatibleConstraintClient(temperature=temperature)
    return PersistenceConstraintAnalyzer(client).analyze(
        prepared,
        evidence_file=evidence_file,
        limit=limit,
    )


def _write_model(path: Path, model: object) -> None:
    _write_text(path, model.model_dump_json(indent=2) + "\n")  # type: ignore[attr-defined]


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _configure_logging(level_name: str) -> None:
    normalized = level_name.upper()
    level = getattr(logging, normalized, None)
    if not isinstance(level, int):
        raise typer.BadParameter(f"Unsupported log level {level_name!r}.")
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        force=True,
    )


if __name__ == "__main__":
    app()
