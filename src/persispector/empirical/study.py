"""Prepare frozen evidence and assess it with one structured LLM."""

from __future__ import annotations

import logging
from pathlib import Path
from time import monotonic
from typing import Any, Iterable

from cldk import CLDK
from cldk.analysis import AnalysisLevel
from cldk.analysis.java import JavaAnalysis

from persispector.empirical.dependencies import load_ipd_records
from persispector.empirical.grounding import SourceEvidenceBuilder
from persispector.empirical.models import (
    AssessmentRecord,
    EvidenceBundle,
    IPDAssessment,
    IPDRecord,
    PreparedStudy,
)
from persispector.empirical.provider import AssessmentClient


logger = logging.getLogger(__name__)


class EvidencePreparer:
    def __init__(
        self,
        analysis: JavaAnalysis,
        project_path: str | Path,
        **builder_options: Any,
    ):
        self.analysis = analysis
        self.project_path = Path(project_path).resolve()
        self.builder = SourceEvidenceBuilder(
            analysis, self.project_path, **builder_options
        )

    @classmethod
    def from_project(
        cls,
        project_path: str | Path,
        *,
        analysis_json_path: str | Path | None = None,
        eager: bool = False,
        **builder_options: Any,
    ) -> "EvidencePreparer":
        project = Path(project_path).resolve()
        analysis = CLDK(language="java").analysis(
            project_path=project,
            analysis_level=AnalysisLevel.symbol_table,
            analysis_json_path=analysis_json_path,
            eager=eager,
        )
        return cls(analysis, project, **builder_options)

    def prepare(self, records: Iterable[IPDRecord]) -> list[EvidenceBundle]:
        return [self.builder.build(record) for record in records]

    def prepare_file(
        self, dependency_file: str | Path, application: str
    ) -> PreparedStudy:
        cases = self.prepare(load_ipd_records(dependency_file, application))
        return PreparedStudy(
            application=application,
            project_path=str(self.project_path),
            dependency_file=str(Path(dependency_file).resolve()),
            cases=cases,
        )


class StudyAssessor:
    """Run one structured, source-grounded LLM assessment."""

    def __init__(self, client: AssessmentClient):
        self.client = client

    def assess(self, bundle: EvidenceBundle) -> AssessmentRecord:
        assessment = self.client.assess(bundle)
        validate_grounding(assessment, bundle)
        return AssessmentRecord(
            case_id=bundle.case_id,
            prompt_version=bundle.prompt_version,
            model=self.client.model_name,
            assessment=assessment,
        )

    def assess_all(
        self, bundles: Iterable[EvidenceBundle]
    ) -> list[AssessmentRecord]:
        cases = list(bundles)
        total = len(cases)
        logger.info(
            "Starting IPD assessment batch: cases=%d model=%s",
            total,
            self.client.model_name,
        )
        records: list[AssessmentRecord] = []
        batch_started = monotonic()
        for index, bundle in enumerate(cases, start=1):
            case_started = monotonic()
            logger.info(
                "Assessing case %d/%d: %s %s case_id=%s",
                index,
                total,
                bundle.case.http_method.upper(),
                bundle.case.path,
                bundle.case_id,
            )
            try:
                record = self.assess(bundle)
            except Exception as error:
                logger.error(
                    "Assessment failed for case %d/%d: case_id=%s "
                    "error_type=%s elapsed=%.1fs",
                    index,
                    total,
                    bundle.case_id,
                    type(error).__name__,
                    monotonic() - case_started,
                )
                raise
            records.append(record)
            logger.info(
                "Completed case %d/%d: case_id=%s conclusion=%s "
                "confidence=%.2f elapsed=%.1fs",
                index,
                total,
                bundle.case_id,
                record.assessment.overall_conclusion,
                record.assessment.confidence,
                monotonic() - case_started,
            )
        logger.info(
            "Completed IPD assessment batch: cases=%d elapsed=%.1fs",
            total,
            monotonic() - batch_started,
        )
        return records


def validate_grounding(assessment: IPDAssessment, bundle: EvidenceBundle) -> None:
    valid_ids = {
        item.evidence_id for item in bundle.code_evidence
    } | {item.evidence_id for item in bundle.persistence_hints}
    cited_ids = set(assessment.evidence_ids)
    for operation in assessment.persistent_operations:
        cited_ids.update(operation.evidence_ids)
    unknown = cited_ids - valid_ids
    if unknown:
        raise ValueError(f"Assessment cites unknown evidence IDs: {sorted(unknown)}")
    positive = (
        assessment.traceable_to_persistent_constraint == "yes"
        or assessment.inferable_from_persistent_operations == "yes"
    )
    if positive and not cited_ids:
        raise ValueError("A positive persistence judgment must cite source evidence.")
    known_parameters = set(bundle.dependency_parameters)
    for match in bundle.operation_matches:
        known_parameters.update(match.operation_parameters)
    claimed_parameters = set(assessment.involved_parameters)
    for operation in assessment.persistent_operations:
        claimed_parameters.update(operation.parameters)
    unknown_parameters = claimed_parameters - known_parameters
    if unknown_parameters:
        raise ValueError(
            "Assessment claims parameters not present in the IPD or resolved operation: "
            f"{sorted(unknown_parameters)}"
        )
