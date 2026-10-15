"""Serializable contracts for agent-driven runtime verification."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


VERIFICATION_SCHEMA_VERSION = "persistence-runtime-verification-v2"
TASK_SCHEMA_VERSION = "persistence-verification-task-v1"

AgentExecutionStatus = Literal[
    "complete",
    "blocked",
    "needs-approval",
    "needs-credentials",
    "needs-funds",
    "failed",
]
AgentRunExecutionStatus = Literal[
    "complete",
    "blocked",
    "rate-limited",
    "needs-approval",
    "needs-credentials",
    "needs-funds",
    "failed",
    "timed-out",
    "invalid-output",
]
VerificationCoverageStatus = Literal["complete", "partial", "none"]
RuntimeOutcome = Literal[
    "APPLICATION_REJECTED",
    "APPLICATION_TRANSFORMED",
    "DATABASE_ENFORCED_HANDLED",
    "DATABASE_ENFORCED_UNHANDLED",
    "NO_OBSERVED_ENFORCEMENT",
    "INCONCLUSIVE_PRE_PERSISTENCE_FAILURE",
    "NOT_API_CONTROLLABLE",
    "STRUCTURAL_NOT_RUNTIME_PREDICATE",
    "VARIANT_NOT_DEPLOYED",
    "BLOCKED_EXTERNAL_DEPENDENCY",
    "CONTROL_ONLY",
]
TargetKind = Literal["constraint", "dependency"]
EvidenceKind = Literal[
    "http-exchange",
    "application-log",
    "database-log",
    "read-back",
    "sql-trace",
    "deployment-log",
    "patch",
    "source",
    "other",
]
CasePurpose = Literal["setup", "control", "violation", "boundary", "read-back"]


class VerificationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VerificationPolicy(VerificationModel):
    """Safety and resource limits communicated to the delegated agent."""

    schema_version: str = TASK_SCHEMA_VERSION
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost"]
    )
    allowed_ports: list[int] = Field(default_factory=list)
    allow_dependency_downloads: bool = False
    allow_external_services: bool = False
    allow_source_patches: bool = True
    require_isolated_workspace: bool = True
    max_runtime_seconds: int = 7_200
    max_agent_turns: int = 200
    max_budget_usd: float | None = None
    notes: list[str] = Field(default_factory=list)


class VerificationTaskManifest(VerificationModel):
    """Inputs and paths for one application-level agent assignment."""

    schema_version: str = TASK_SCHEMA_VERSION
    task_id: str
    application: str
    created_at: datetime
    source_project_path: str
    task_directory: str
    application_directory: str
    output_directory: str
    supervisor_directory: str
    constraint_report: str
    taint_report: str | None = None
    target_ids: list[str] = Field(default_factory=list)
    policy_file: str
    instructions_file: str
    result_schema_file: str
    deployment_schema_file: str
    verification_results_schema_file: str


class EvidenceReference(VerificationModel):
    """A path relative to the verification output directory."""

    path: str = Field(min_length=1)
    kind: EvidenceKind
    description: str = Field(min_length=1)
    sha256: str | None = None


class VerificationCase(VerificationModel):
    case_id: str
    purpose: CasePurpose
    target_ids: list[str] = Field(default_factory=list)
    endpoint: str | None = None
    request_method: str | None = None
    request_url: str | None = None
    response_status: int | None = None
    reached_persistence: bool | None = None
    evidence: list[EvidenceReference] = Field(default_factory=list)
    observation: str = Field(min_length=1)


class TargetVerification(VerificationModel):
    target_id: str
    target_kind: TargetKind
    outcome: RuntimeOutcome
    exact_predicate_confirmed: bool
    observed_enforcement: Literal[
        "application", "database", "none", "not-observed", "not-applicable"
    ]
    application_layer_implemented: bool | None
    response_handling: Literal[
        "elegant", "unhandled", "accepted", "not-assessed", "not-applicable"
    ]
    case_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    rationale: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_semantics(self) -> "TargetVerification":
        confirming = {
            "APPLICATION_REJECTED",
            "APPLICATION_TRANSFORMED",
            "DATABASE_ENFORCED_HANDLED",
            "DATABASE_ENFORCED_UNHANDLED",
        }
        if self.exact_predicate_confirmed != (self.outcome in confirming):
            raise ValueError(
                "exact_predicate_confirmed must agree with the runtime outcome"
            )
        if self.outcome.startswith("DATABASE_ENFORCED"):
            if self.observed_enforcement != "database":
                raise ValueError("database outcomes require database enforcement")
            if self.application_layer_implemented is not False:
                raise ValueError("database outcomes are not application-layer enforcement")
            expected_handling = (
                "elegant"
                if self.outcome == "DATABASE_ENFORCED_HANDLED"
                else "unhandled"
            )
            if self.response_handling != expected_handling:
                raise ValueError(
                    f"{self.outcome} requires response_handling={expected_handling}"
                )
        if self.outcome.startswith("APPLICATION_"):
            if self.observed_enforcement != "application":
                raise ValueError("application outcomes require application enforcement")
            if self.application_layer_implemented is not True:
                raise ValueError("application outcomes require application implementation")
            if self.response_handling != "elegant":
                raise ValueError("application enforcement requires elegant handling")
        if self.outcome == "NO_OBSERVED_ENFORCEMENT":
            if self.observed_enforcement not in {"none", "not-observed"}:
                raise ValueError("no-enforcement outcomes cannot name an enforcement layer")
            if self.application_layer_implemented is not False:
                raise ValueError("no-enforcement outcomes require no application implementation")
            if self.response_handling != "accepted":
                raise ValueError("no-enforcement outcomes require accepted handling")
        return self


class DeploymentCommand(VerificationModel):
    purpose: str
    command: str
    working_directory: str
    exit_code: int | None = None


class DeploymentManifest(VerificationModel):
    schema_version: str = VERIFICATION_SCHEMA_VERSION
    application: str
    source_revision: str | None = None
    isolated_application_path: str
    build_system: str | None = None
    java_version: str | None = None
    runtime_database: str | None = None
    schema_context_id: str | None = None
    base_urls: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    health_checks: list[str] = Field(default_factory=list)
    commands: list[DeploymentCommand] = Field(default_factory=list)
    patches: list[EvidenceReference] = Field(default_factory=list)
    logs: list[EvidenceReference] = Field(default_factory=list)
    cleanup_performed: bool = False
    notes: list[str] = Field(default_factory=list)


class VerificationReport(VerificationModel):
    schema_version: str = VERIFICATION_SCHEMA_VERSION
    application: str
    constraint_report_schema_version: str
    generated_at: datetime
    target_ids: list[str]
    cases: list[VerificationCase] = Field(default_factory=list)
    results: list[TargetVerification] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class AgentCompletion(VerificationModel):
    """Small, schema-constrained final message returned by Claude Code."""

    schema_version: str = VERIFICATION_SCHEMA_VERSION
    execution_status: AgentExecutionStatus
    coverage_status: VerificationCoverageStatus
    application: str
    deployment_manifest: str = "deployment.json"
    verification_results: str = "verification-results.json"
    summary: str
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def upgrade_legacy_status(cls, value):
        """Read v1 completions while exposing separate v2 status dimensions."""

        if not isinstance(value, dict) or "status" not in value:
            return value
        result = dict(value)
        legacy = result.pop("status")
        if "execution_status" not in result:
            result["execution_status"] = (
                "complete" if legacy == "partial" else legacy
            )
        if "coverage_status" not in result:
            result["coverage_status"] = (
                "complete"
                if legacy == "complete"
                else "partial"
                if legacy == "partial"
                else "none"
            )
        return result

    @property
    def status(self) -> str:
        """Legacy combined status retained for Python API compatibility."""

        if self.execution_status == "complete" and self.coverage_status != "complete":
            return "partial"
        return self.execution_status


class AgentRunRecord(VerificationModel):
    schema_version: str = VERIFICATION_SCHEMA_VERSION
    run_id: str
    application: str
    execution_status: AgentRunExecutionStatus
    coverage_status: VerificationCoverageStatus
    started_at: datetime
    finished_at: datetime
    command: list[str]
    working_directory: str
    session_id: str | None = None
    resumed_from: str | None = None
    exit_code: int | None = None
    total_cost_usd: float | None = None
    turns: int | None = None
    events_file: str
    stderr_file: str
    completion: AgentCompletion | None = None
    error: str | None = None

    @model_validator(mode="before")
    @classmethod
    def upgrade_legacy_status(cls, value):
        """Read run records written before status and coverage were separated."""

        if not isinstance(value, dict) or "status" not in value:
            return value
        result = dict(value)
        legacy = result.pop("status")
        if "execution_status" not in result:
            result["execution_status"] = (
                "complete" if legacy == "partial" else legacy
            )
        if "coverage_status" not in result:
            completion = result.get("completion")
            completion_coverage = (
                completion.get("coverage_status")
                if isinstance(completion, dict)
                else None
            )
            result["coverage_status"] = completion_coverage or (
                "complete"
                if legacy == "complete"
                else "partial"
                if legacy == "partial"
                else "none"
            )
        return result

    @property
    def status(self) -> str:
        """Legacy combined status retained for Python API compatibility."""

        if self.execution_status == "complete" and self.coverage_status != "complete":
            return "partial"
        return self.execution_status


class AgentState(VerificationModel):
    schema_version: str = VERIFICATION_SCHEMA_VERSION
    application: str
    task_id: str
    runs: list[AgentRunRecord] = Field(default_factory=list)


class ValidationIssue(VerificationModel):
    severity: Literal["error", "warning"]
    code: str
    message: str
    target_id: str | None = None
    path: str | None = None


class ValidationReport(VerificationModel):
    schema_version: str = VERIFICATION_SCHEMA_VERSION
    valid: bool
    checked_at: datetime
    target_count: int
    result_count: int
    issues: list[ValidationIssue] = Field(default_factory=list)


class VerificationExecution(VerificationModel):
    schema_version: str = VERIFICATION_SCHEMA_VERSION
    task: VerificationTaskManifest
    final_run: AgentRunRecord
    validation: ValidationReport
    resume_count: int = 0
