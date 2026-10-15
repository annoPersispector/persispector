"""Structured LLM extraction and deterministic report aggregation."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Iterable, Protocol

from langchain_core.prompts import ChatPromptTemplate

from persispector.llm import (
    chat_model,
    configure_llm_cache,
    environment_model,
    invoke_structured_with_retries,
)
from persispector.persistence.discovery import PersistenceEvidencePreparer
from persispector.persistence.modeling import attach_findings_to_models
from persispector.persistence.endpoint_access import (
    refresh_endpoint_parameter_matches,
)
from persispector.persistence.codeql_flow import refresh_codeql_taint_links
from persispector.persistence.models import (
    ConstraintExtraction,
    ConstraintFinding,
    ConstraintGroup,
    EvidenceArtifact,
    ExtractedConstraint,
    ExtractionFailure,
    ModelCorrelation,
    PersistenceConstraintReport,
    PreparedPersistenceEvidence,
)
from persispector.persistence.prompts import (
    HUMAN_PROMPT,
    SYSTEM_PROMPT,
    extraction_variables,
)


logger = logging.getLogger(__name__)


class ConstraintExtractionClient(Protocol):
    model_name: str

    def extract(self, artifact: EvidenceArtifact) -> ConstraintExtraction: ...


class OpenAICompatibleConstraintClient:
    """OpenAI-compatible structured client using shared project settings."""

    def __init__(
        self,
        *,
        model_env: str = "PERSISTENCE_MODEL",
        temperature: float = 0.0,
    ):
        self.model_name = environment_model(model_env)
        self.temperature = temperature
        self._chain = None

    def extract(self, artifact: EvidenceArtifact) -> ConstraintExtraction:
        if self._chain is None:
            configure_llm_cache()
            llm = chat_model(
                self.model_name, self.temperature
            ).with_structured_output(
                ConstraintExtraction,
                method="function_calling",
            )
            self._chain = ChatPromptTemplate.from_messages(
                [("system", SYSTEM_PROMPT), ("human", HUMAN_PROMPT)]
            ) | llm
        return invoke_structured_with_retries(
            self._chain,
            extraction_variables(artifact),
            ConstraintExtraction,
            operation="Persistence constraint extraction",
            validate=lambda result: validate_extraction_contract(result, artifact),
            log=logger,
        )


class PersistenceConstraintAnalyzer:
    """Combine deterministic findings with LLM extraction of residual evidence."""

    def __init__(self, client: ConstraintExtractionClient):
        self.client = client

    def analyze(
        self,
        prepared: PreparedPersistenceEvidence,
        *,
        evidence_file: str | Path | None = None,
        limit: int | None = None,
    ) -> PersistenceConstraintReport:
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative.")
        artifacts = prepared.artifacts[:limit] if limit is not None else prepared.artifacts
        findings: list[ConstraintFinding] = []
        failures: list[ExtractionFailure] = []
        artifact_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
        deterministic_by_artifact: dict[str, list[ExtractedConstraint]] = {}
        for constraint in prepared.deterministic_constraints:
            evidence_id = constraint.evidence_ids[0]
            if evidence_id in artifact_by_id:
                deterministic_by_artifact.setdefault(evidence_id, []).append(constraint)
        for evidence_id, constraints in deterministic_by_artifact.items():
            artifact = artifact_by_id[evidence_id]
            validated = validate_extraction_contract(
                ConstraintExtraction(constraints=constraints),
                artifact,
                validate_model_ids=False,
            )
            findings.extend(
                self._finding(item, artifact, index, origin="deterministic")
                for index, item in enumerate(validated.constraints, start=1)
            )
        logger.info(
            "Starting persistence analysis: artifacts=%d deterministic=%d model=%s",
            len(artifacts), len(findings), self.client.model_name,
        )
        analyzed = sum(not artifact.llm_required for artifact in artifacts)
        llm_analyzed = 0
        for index, artifact in enumerate(artifacts, start=1):
            if not artifact.llm_required:
                logger.info(
                    "Skipping model for deterministically complete artifact %d/%d: %s",
                    index, len(artifacts), artifact.source.file_path,
                )
                continue
            logger.info(
                "Analyzing residual artifact %d/%d: %s %s",
                index, len(artifacts), artifact.kind, artifact.source.file_path,
            )
            try:
                model_artifact = artifact.model_copy(
                    update={
                        "content": artifact.llm_content or artifact.content,
                        # Keep the provider-facing object single-copy even for
                        # custom clients that serialize the complete model.
                        "llm_content": None,
                    }
                )
                extraction = self.client.extract(model_artifact)
                validated = validate_extraction_contract(extraction, artifact)
            except Exception as error:
                failures.append(
                    ExtractionFailure(
                        artifact_id=artifact.artifact_id,
                        error_type=type(error).__name__,
                        message=str(error),
                    )
                )
                logger.error(
                    "Artifact extraction failed: artifact_id=%s error_type=%s",
                    artifact.artifact_id, type(error).__name__,
                )
                continue
            analyzed += 1
            llm_analyzed += 1
            llm_findings = [
                self._finding(item, artifact, item_index, origin="llm")
                for item_index, item in enumerate(validated.constraints, start=1)
            ]
            findings.extend(
                _without_deterministic_duplicates(
                    findings, llm_findings, artifact.artifact_id
                )
            )
        groups = aggregate_findings(findings, prepared.models.correlations)
        warnings = list(prepared.warnings)
        if limit is not None and limit < len(prepared.artifacts):
            warnings.append(
                f"Analysis limited to {len(artifacts)} of {len(prepared.artifacts)} artifacts."
            )
        if failures:
            warnings.append(
                f"{len(failures)} artifact(s) failed extraction; the report is partial."
            )
        report_models = attach_findings_to_models(
            prepared.models, findings, prepared.artifacts
        )
        report_models = refresh_endpoint_parameter_matches(report_models)
        report_models = refresh_codeql_taint_links(report_models)
        return PersistenceConstraintReport(
            prompt_version=prepared.prompt_version,
            project_path=prepared.project_path,
            evidence_file=str(Path(evidence_file).resolve()) if evidence_file else None,
            model=self.client.model_name,
            artifacts_total=len(prepared.artifacts),
            artifacts_analyzed=analyzed,
            artifacts_llm_analyzed=llm_analyzed,
            deterministic_findings=sum(item.origin == "deterministic" for item in findings),
            llm_findings=sum(item.origin == "llm" for item in findings),
            findings=findings,
            groups=groups,
            failures=failures,
            warnings=warnings,
            skipped_inputs=prepared.skipped_inputs,
            models=report_models,
        )

    @staticmethod
    def _finding(
        extracted: ExtractedConstraint,
        artifact: EvidenceArtifact,
        index: int,
        *,
        origin: str = "llm",
    ) -> ConstraintFinding:
        payload = extracted.model_dump_json(exclude={"confidence"})
        raw = "\0".join((artifact.artifact_id, str(index), payload))
        finding_id = "pc-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return ConstraintFinding(
            finding_id=finding_id,
            sources=[artifact.source],
            origin=origin,
            **extracted.model_dump(),
        )


def _without_deterministic_duplicates(
    existing: list[ConstraintFinding],
    candidates: list[ConstraintFinding],
    artifact_id: str,
) -> list[ConstraintFinding]:
    """Prefer exact deterministic findings when a residual model repeats one."""

    deterministic_signatures = {
        _finding_signature(item)
        for item in existing
        if item.origin == "deterministic" and artifact_id in item.evidence_ids
    }
    return [
        candidate for candidate in candidates
        if _finding_signature(candidate) not in deterministic_signatures
    ]


def _finding_signature(finding: ConstraintFinding) -> str:
    return finding.model_dump_json(
        exclude={"finding_id", "sources", "confidence", "origin", "notes"}
    )


def validate_extraction_contract(
    extraction: ConstraintExtraction,
    artifact: EvidenceArtifact,
    *,
    validate_model_ids: bool = True,
) -> ConstraintExtraction:
    """Validate grounding and layer semantics for one artifact."""

    allowed_layers = (
        {"orm", "validation"}
        if artifact.kind == "java-mapped-type"
        else {"schema"}
    )
    expected_enforcement = {
        "orm": "orm-schema-intent",
        "schema": "database",
        "validation": "application-validation",
    }
    for finding in extraction.constraints:
        unknown = set(finding.evidence_ids) - {artifact.artifact_id}
        if unknown:
            raise ValueError(
                f"Extraction cites unknown evidence IDs: {sorted(unknown)}"
            )
        if finding.layer not in allowed_layers:
            raise ValueError(
                f"Layer {finding.layer!r} is invalid for {artifact.kind}."
            )
        if finding.enforcement != expected_enforcement[finding.layer]:
            raise ValueError(
                f"Enforcement {finding.enforcement!r} does not match layer {finding.layer!r}."
            )
        if validate_model_ids:
            valid_model_ids = set(
                artifact.model_context.get("valid_model_element_ids", [])
            )
            unknown_model_ids = set(finding.model_element_ids) - valid_model_ids
            if unknown_model_ids:
                raise ValueError(
                    "Extraction cites unknown model element IDs: "
                    f"{sorted(unknown_model_ids)}"
                )
        if finding.layer == "schema":
            finding.subject.table_explicit = bool(finding.subject.table)
            finding.subject.columns_explicit = bool(finding.subject.columns)
            finding.subject.schema_context_id = artifact.metadata.get(
                "db_schema_context_id"
            )
        elif artifact.kind == "java-mapped-type":
            subject = finding.subject
            if subject.table_explicit and not _quoted_name(
                subject.table, artifact.content
            ):
                subject.table_explicit = False
                finding.notes.append(
                    "Physical table name was not verified as an explicit Java declaration."
                )
            if subject.columns_explicit and not all(
                _quoted_name(column, artifact.content) for column in subject.columns
            ):
                subject.columns_explicit = False
                finding.notes.append(
                    "One or more physical column names were not verified as explicit Java declarations."
                )
    return extraction


def _quoted_name(name: str | None, content: str) -> bool:
    if not name:
        return False
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    single_escaped = name.replace("\\", "\\\\").replace("'", "\\'")
    return f'"{escaped}"' in content or f"'{single_escaped}'" in content


def aggregate_findings(
    findings: Iterable[ConstraintFinding],
    correlations: Iterable[ModelCorrelation] = (),
) -> list[ConstraintGroup]:
    canonical_ids: dict[str, str] = {}
    targets_by_orm: dict[str, set[str]] = {}
    for correlation in correlations:
        if correlation.status != "matched" or not correlation.db_schema_element_id:
            continue
        targets_by_orm.setdefault(correlation.orm_element_id, set()).add(
            correlation.db_schema_element_id
        )
        canonical_ids[correlation.db_schema_element_id] = (
            correlation.db_schema_element_id
        )
    # Canonicalize across layers only when an ORM element has one unambiguous
    # physical counterpart. An ORM type mapped to MySQL and PostgreSQL schemas
    # must not cause those alternative tables to collapse into one group.
    for orm_id, targets in targets_by_orm.items():
        if len(targets) == 1:
            canonical_ids[orm_id] = next(iter(targets))
    buckets: dict[str, list[ConstraintFinding]] = {}
    for finding in findings:
        key = _group_key(finding, canonical_ids)
        buckets.setdefault(key, []).append(finding)
    groups: list[ConstraintGroup] = []
    for key, items in sorted(buckets.items()):
        reason = _conflict_reason(items)
        status = "single" if len(items) == 1 else "conflict" if reason else "consistent"
        group_id = "pg-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        groups.append(
            ConstraintGroup(
                group_id=group_id,
                key=key,
                finding_ids=[item.finding_id for item in items],
                status=status,
                reason=reason,
            )
        )
    return groups


def _group_key(
    finding: ConstraintFinding, canonical_ids: dict[str, str] | None = None
) -> str:
    canonical_ids = canonical_ids or {}
    modeled = [
        canonical_ids.get(model_id, model_id)
        for model_id in finding.model_element_ids
    ]
    if modeled:
        # Include the full correlated subject. Using only the final column
        # would merge UNIQUE(b) with UNIQUE(a, b), for example.
        return ":".join(("model", *dict.fromkeys(modeled), finding.kind))
    subject = finding.subject
    if subject.table and subject.table_explicit:
        columns = subject.columns if subject.columns_explicit else []
        return ":".join(
            (
                "physical",
                subject.schema_context_id or "unknown-context",
                subject.table.lower(),
                ",".join(item.lower() for item in columns) or "*",
                finding.kind,
            )
        )
    if subject.entity:
        members = ",".join(item.lower() for item in subject.fields) or "*"
        return ":".join(("entity", subject.entity.lower(), members, finding.kind))
    location = ",".join(finding.evidence_ids)
    return ":".join(("unlinked", location, finding.kind))


def _conflict_reason(items: list[ConstraintFinding]) -> str | None:
    if len(items) < 2:
        return None
    kind = items[0].kind
    details = [item.details for item in items]
    if kind == "foreign-key":
        table_targets = {
            (detail.referenced_table, tuple(detail.referenced_columns))
            for detail in details
            if detail.referenced_table
        }
        entity_targets = {
            (detail.referenced_entity, tuple(detail.referenced_fields))
            for detail in details
            if detail.referenced_entity
        }
        # A logical entity target and a physical table target are not directly
        # comparable unless their target objects are explicitly correlated.
        # Source correlation alone must not manufacture a target conflict.
        if len(table_targets) > 1 or len(entity_targets) > 1:
            return "Foreign-key declarations reference different targets."
        if table_targets and entity_targets:
            return None
        targets = {
            (
                detail.referenced_table or detail.referenced_entity,
                tuple(detail.referenced_columns or detail.referenced_fields),
            )
            for detail in details
            if detail.referenced_table or detail.referenced_entity
        }
        if len(targets) > 1:
            return "Foreign-key declarations reference different targets."
    scalar_fields = {
        "type": ("column_type",),
        "length": ("length",),
        "precision-scale": ("precision", "scale"),
        "referential-action": ("on_delete", "on_update"),
    }.get(kind, ())
    if scalar_fields:
        values = {
            tuple(getattr(detail, field) for field in scalar_fields)
            for detail in details
            if any(getattr(detail, field) is not None for field in scalar_fields)
        }
        if len(values) > 1:
            return f"{kind} declarations specify different values."
    if kind == "range":
        minima = [detail.minimum for detail in details if detail.minimum is not None]
        maxima = [detail.maximum for detail in details if detail.maximum is not None]
        if minima and maxima and max(minima) > min(maxima):
            return "Declared numeric ranges do not overlap."
    return None


def analyze_persistence_project(
    project_path: str | Path,
    *,
    client: ConstraintExtractionClient | None = None,
    analysis_json_path: str | Path | None = None,
    eager: bool = False,
    temperature: float = 0.0,
    **prepare_options: object,
) -> PersistenceConstraintReport:
    """Convenience Python API for the complete in-memory workflow."""

    prepared = PersistenceEvidencePreparer.from_project(
        project_path,
        analysis_json_path=analysis_json_path,
        eager=eager,
        **prepare_options,
    ).prepare()
    selected_client = client or OpenAICompatibleConstraintClient(
        temperature=temperature
    )
    return PersistenceConstraintAnalyzer(selected_client).analyze(prepared)
