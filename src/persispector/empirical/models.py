"""Serializable models for the empirical IPD study."""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, Field, model_validator


PROMPT_VERSION = "persistence-grounded-ipd-v1"


class IPDRecord(BaseModel):
    application: str
    path: str
    http_method: str
    dependency: str
    source_file: str | None = None

    @property
    def case_id(self) -> str:
        raw = "\0".join(
            (self.application, self.path, self.http_method.upper(), self.dependency)
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class OperationMatch(BaseModel):
    resolution: Literal[
        "exact", "path-template", "heuristic-route-dispatch", "ambiguous", "not-found"
    ]
    requested_path: str
    requested_method: str
    resolved_path: str | None = None
    symbol: str | None = None
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    operation_parameters: list[str] = Field(default_factory=list)
    candidate_symbols: list[str] = Field(default_factory=list)


class CodeEvidence(BaseModel):
    evidence_id: str
    kind: Literal[
        "endpoint",
        "route-dispatch",
        "reachable-method",
        "parameter-mention",
        "persistence-method",
    ]
    symbol: str
    file_path: str
    start_line: int
    end_line: int
    code: str
    depth: int | None = None
    relevance: list[str] = Field(default_factory=list)
    truncated: bool = False


class PersistenceHint(BaseModel):
    evidence_id: str
    kind: Literal["read", "create", "update", "delete", "query", "transaction"]
    symbol: str
    file_path: str
    line: int
    expression: str
    related_parameters: list[str] = Field(default_factory=list)
    basis: str


class EvidenceBundle(BaseModel):
    case: IPDRecord
    case_id: str
    project_path: str
    prompt_version: str = PROMPT_VERSION
    dependency_parameters: list[str] = Field(default_factory=list)
    operation_matches: list[OperationMatch] = Field(default_factory=list)
    code_evidence: list[CodeEvidence] = Field(default_factory=list)
    persistence_hints: list[PersistenceHint] = Field(default_factory=list)
    unresolved_calls: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


Conclusion = Literal["yes", "no", "unclear"]
OverallConclusion = Literal[
    "persistence-grounded", "not-persistence-grounded", "unclear"
]
IPDCategory = Literal[
    "joint-query",
    "cross-entity-consistency",
    "relationship-validity",
    "state-conditioned",
    "conditional-persistence",
    "mutation-coordination",
    "query-shaping",
    "mutation-shaping",
    "parameter-only-validation",
    "other",
    "not-applicable",
]


class InferredPersistentOperation(BaseModel):
    kind: Literal["read", "create", "update", "delete", "query", "transaction"]
    entity_or_store: str
    predicate_or_effect: str
    parameters: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class IPDAssessment(BaseModel):
    """Structured LLM judgment for one supplied inter-parameter dependency."""

    overall_conclusion: OverallConclusion
    traceable_to_persistent_constraint: Conclusion = Field(
        description=(
            "Whether the supplied IPD is implemented as a constraint involving "
            "persistent entities, values, relationships, or state."
        )
    )
    inferable_from_persistent_operations: Conclusion = Field(
        description=(
            "Whether the supplied IPD could be inferred from the semantics or shape "
            "of persistent reads/writes, even if validation occurs elsewhere."
        )
    )
    category: IPDCategory
    involved_parameters: list[str]
    normalized_constraint: str
    persistent_operations: list[InferredPersistentOperation] = Field(default_factory=list)
    reasoning: str
    evidence_ids: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def conclusions_are_consistent(self) -> "IPDAssessment":
        yes = (
            self.traceable_to_persistent_constraint == "yes"
            or self.inferable_from_persistent_operations == "yes"
        )
        both_no = (
            self.traceable_to_persistent_constraint == "no"
            and self.inferable_from_persistent_operations == "no"
        )
        if self.overall_conclusion == "persistence-grounded" and not yes:
            raise ValueError("A persistence-grounded conclusion requires at least one yes.")
        if self.overall_conclusion == "not-persistence-grounded" and not both_no:
            raise ValueError("A negative overall conclusion requires two no judgments.")
        return self


class AssessmentRecord(BaseModel):
    case_id: str
    prompt_version: str
    model: str
    assessment: IPDAssessment


class PreparedStudy(BaseModel):
    application: str
    project_path: str
    dependency_file: str
    prompt_version: str = PROMPT_VERSION
    cases: list[EvidenceBundle]


class CompletedStudy(BaseModel):
    application: str
    prompt_version: str
    evidence_file: str
    assessments: list[AssessmentRecord]
