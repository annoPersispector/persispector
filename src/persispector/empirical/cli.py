"""CLI for preparing and assessing persistence-grounded IPD study cases."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

import typer

from persispector.empirical.models import CompletedStudy, PreparedStudy
from persispector.empirical.provider import OpenAICompatibleAssessmentClient
from persispector.empirical.study import EvidencePreparer, StudyAssessor


logger = logging.getLogger(__name__)


app = typer.Typer(
    add_completion=False,
    help="Prepare and assess persistence-grounded inter-parameter dependencies.",
)


@app.command()
def prepare(
    project: Annotated[Path, typer.Argument(help="Java project or source-module root.")],
    dependencies: Annotated[Path, typer.Option("--dependencies", "-d")],
    application: Annotated[str, typer.Option("--application", "-a")],
    output: Annotated[Path, typer.Option("--output", "-o")],
    analysis_cache: Annotated[Path | None, typer.Option(help="CLDK analysis cache directory.")] = None,
    eager: Annotated[bool, typer.Option(help="Refresh the CLDK analysis cache.")] = False,
    max_depth: Annotated[int, typer.Option(help="Maximum application-call depth.")] = 4,
    max_methods: Annotated[int, typer.Option(help="Maximum snippets per IPD.")] = 30,
    max_total_chars: Annotated[int, typer.Option(help="Maximum source characters per IPD.")] = 48_000,
) -> None:
    """Freeze source-grounded evidence without contacting an LLM provider."""

    preparer = EvidencePreparer.from_project(
        project,
        analysis_json_path=analysis_cache,
        eager=eager,
        max_depth=max_depth,
        max_methods=max_methods,
        max_total_chars=max_total_chars,
    )
    study = preparer.prepare_file(dependencies, application)
    _write_model(output, study)


@app.command()
def assess(
    evidence: Annotated[Path, typer.Argument(help="Prepared-study JSON from `prepare`.")],
    output: Annotated[Path, typer.Option("--output", "-o")],
    temperature: Annotated[float, typer.Option(help="Model sampling temperature.")] = 0.1,
    limit: Annotated[int | None, typer.Option(help="Assess only the first N cases.")] = None,
    log_level: Annotated[
        str,
        typer.Option(help="Logging level: DEBUG, INFO, WARNING, ERROR, or CRITICAL."),
    ] = "INFO",
) -> None:
    """Assess frozen evidence with structured OpenAI-compatible model calls."""

    _configure_logging(log_level)
    prepared = PreparedStudy.model_validate_json(evidence.read_text(encoding="utf-8"))
    cases = prepared.cases[:limit] if limit is not None else prepared.cases
    logger.info(
        "Loaded prepared study: application=%s selected_cases=%d total_cases=%d",
        prepared.application,
        len(cases),
        len(prepared.cases),
    )
    client = OpenAICompatibleAssessmentClient(
        model_env="IPD_STUDY_MODEL",
        temperature=temperature,
    )
    logger.info(
        "Configured assessment model: model=%s temperature=%.2f",
        client.model_name,
        temperature,
    )
    assessor = StudyAssessor(client)
    completed = CompletedStudy(
        application=prepared.application,
        prompt_version=prepared.prompt_version,
        evidence_file=str(evidence.resolve()),
        assessments=assessor.assess_all(cases),
    )
    _write_model(output, completed)
    logger.info(
        "Wrote assessment results: path=%s assessments=%d",
        output.resolve(),
        len(completed.assessments),
    )


def _configure_logging(level_name: str) -> None:
    normalized = level_name.upper()
    level = getattr(logging, normalized, None)
    if not isinstance(level, int):
        raise typer.BadParameter(
            f"Unsupported log level {level_name!r}.",
            param_hint="--log-level",
        )
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        force=True,
    )


def _write_model(path: Path, model: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model.model_dump_json(indent=2) + "\n", encoding="utf-8")  # type: ignore[attr-defined]


if __name__ == "__main__":
    app()
