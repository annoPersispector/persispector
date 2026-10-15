"""Serializable contracts for persistence evidence and reports."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


SCHEMA_VERSION = "9"
PROMPT_VERSION = "declared-persistence-constraints-v5"
MODEL_VERSION = "persistence-model-v7"

ArtifactKind = Literal["java-mapped-type", "sql-ddl", "liquibase-changeset"]
ConstraintLayer = Literal["orm", "schema", "validation"]
Enforcement = Literal["database", "orm-schema-intent", "application-validation"]
ConstraintKind = Literal[
    "primary-key",
    "foreign-key",
    "not-null",
    "unique",
    "composite-unique",
    "check",
    "type",
    "length",
    "precision-scale",
    "range",
    "format-pattern",
    "referential-action",
    "custom",
    "other",
]


class SourceLocation(BaseModel):
    file_path: str
    start_line: int | None = None
    end_line: int | None = None


class EvidenceArtifact(BaseModel):
    artifact_id: str
    kind: ArtifactKind
    source: SourceLocation
    content: str
    mapped_type: str | None = None
    imports: list[str] = Field(default_factory=list)
    truncated: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)
    # New evidence sets are statically analyzed during preparation. The model
    # is contacted only when this flag is true; llm_content then contains the
    # unresolved subset. True remains the default for schema-v1 compatibility.
    llm_required: bool = True
    llm_content: str | None = None
    # A bounded, source-local projection of the intermediate persistence model.
    # It gives residual extraction stable model IDs without sending the complete
    # project model to the provider.
    model_context: dict[str, Any] = Field(default_factory=dict)


class SkippedInput(BaseModel):
    file_path: str
    reason: str


class ConstraintSubject(BaseModel):
    entity: str | None = None
    table: str | None = None
    table_explicit: bool = False
    fields: list[str] = Field(default_factory=list)
    columns: list[str] = Field(default_factory=list)
    columns_explicit: bool = False
    # Identifies the database/module variant that owns a schema declaration.
    # ORM declarations leave this unset because one ORM model can correlate to
    # several alternative physical schemas.
    schema_context_id: str | None = None


class ConstraintDetails(BaseModel):
    referenced_entity: str | None = None
    referenced_table: str | None = None
    referenced_fields: list[str] = Field(default_factory=list)
    referenced_columns: list[str] = Field(default_factory=list)
    column_type: str | None = None
    length: int | None = None
    minimum: float | None = None
    maximum: float | None = None
    precision: int | None = None
    scale: int | None = None
    pattern: str | None = None
    on_delete: str | None = None
    on_update: str | None = None
    custom: dict[str, str] = Field(default_factory=dict)


class ExtractedConstraint(BaseModel):
    layer: ConstraintLayer
    kind: ConstraintKind
    subject: ConstraintSubject
    predicate: str
    details: ConstraintDetails = Field(default_factory=ConstraintDetails)
    enforcement: Enforcement
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    notes: list[str] = Field(default_factory=list)
    model_element_ids: list[str] = Field(default_factory=list)


class ConstraintExtraction(BaseModel):
    constraints: list[ExtractedConstraint] = Field(default_factory=list)


ModelElementKind = Literal[
    "orm-type",
    "orm-attribute",
    "orm-association",
    "db-schema-table",
    "db-schema-column",
]


class NameMapping(BaseModel):
    logical_name: str | None = None
    physical_name: str | None = None
    explicit: bool = False


class ModelElementRef(BaseModel):
    model_id: str | None = None
    kind: ModelElementKind | None = None
    name: str | None = None


class ColumnPair(BaseModel):
    source: str | None = None
    target: str | None = None


class ModeledConstraint(BaseModel):
    constraint_id: str
    owner_ids: list[str] = Field(default_factory=list)
    declaration: ExtractedConstraint
    sources: list[SourceLocation] = Field(default_factory=list)


class ModeledDependency(BaseModel):
    dependency_id: str
    kind: Literal["foreign-key", "association", "embedded", "inheritance"]
    layer: ConstraintLayer
    source: ModelElementRef
    target: ModelElementRef
    column_pairs: list[ColumnPair] = Field(default_factory=list)
    enforcement: Enforcement
    evidence_ids: list[str] = Field(default_factory=list)
    sources: list[SourceLocation] = Field(default_factory=list)
    constraint_ids: list[str] = Field(default_factory=list)


class OrmJoinColumn(BaseModel):
    name: NameMapping
    referenced_column: NameMapping | None = None
    nullable: bool | None = None
    unique: bool | None = None


class OrmAttribute(BaseModel):
    model_id: str
    name: str
    java_type: str
    mapping_kind: Literal[
        "basic", "embedded", "embedded-id", "element-collection"
    ] = "basic"
    column: NameMapping
    constraint_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    sources: list[SourceLocation] = Field(default_factory=list)


class OrmAssociation(BaseModel):
    model_id: str
    member: str
    java_type: str
    relationship: str
    target_entity: str | None = None
    join_columns: list[OrmJoinColumn] = Field(default_factory=list)
    foreign_key_mode: Literal[
        "constraint", "no-constraint", "provider-default", "unspecified"
    ] = "unspecified"
    foreign_key_definition: str | None = None
    constraint_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    sources: list[SourceLocation] = Field(default_factory=list)


class OrmType(BaseModel):
    model_id: str
    qualified_name: str
    declaration_kind: Literal["Entity", "MappedSuperclass", "Embeddable", "mapped"]
    table: NameMapping
    parent_types: list[str] = Field(default_factory=list)
    inheritance_strategy: str | None = None
    discriminator_column: NameMapping | None = None
    attributes: list[OrmAttribute] = Field(default_factory=list)
    associations: list[OrmAssociation] = Field(default_factory=list)
    identifier_attribute_ids: list[str] = Field(default_factory=list)
    constraint_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    sources: list[SourceLocation] = Field(default_factory=list)


class OrmPersistenceModel(BaseModel):
    types: list[OrmType] = Field(default_factory=list)
    constraints: list[ModeledConstraint] = Field(default_factory=list)
    dependencies: list[ModeledDependency] = Field(default_factory=list)


class RelationalColumn(BaseModel):
    model_id: str
    source_model_id: str | None = None
    name: NameMapping
    declared_type: str | None = None
    constraint_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    sources: list[SourceLocation] = Field(default_factory=list)


class RelationalTable(BaseModel):
    model_id: str
    source_model_id: str | None = None
    schema_context_id: str | None = None
    name: NameMapping
    columns: list[RelationalColumn] = Field(default_factory=list)
    constraint_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    sources: list[SourceLocation] = Field(default_factory=list)


class SchemaOperation(BaseModel):
    operation_id: str
    kind: Literal[
        "create-table",
        "alter-table",
        "create-unique-index",
        "add-column",
        "add-constraint",
        "liquibase-change",
        "other",
    ]
    target_table: str | None = None
    target_columns: list[str] = Field(default_factory=list)
    schema_context_id: str | None = None
    sequence: int | None = None
    evidence_id: str
    source: SourceLocation


class DBSchemaContext(BaseModel):
    """One independently deployable module/database schema variant."""

    context_id: str
    key: str
    label: str
    module: str
    variant: str
    evidence_ids: list[str] = Field(default_factory=list)
    sources: list[SourceLocation] = Field(default_factory=list)


class DBSchemaModel(BaseModel):
    resolution_status: Literal[
        "declarations-only", "partially-reconstructed", "ordered-snapshot"
    ] = "declarations-only"
    contexts: list[DBSchemaContext] = Field(default_factory=list)
    tables: list[RelationalTable] = Field(default_factory=list)
    operations: list[SchemaOperation] = Field(default_factory=list)
    constraints: list[ModeledConstraint] = Field(default_factory=list)
    dependencies: list[ModeledDependency] = Field(default_factory=list)


class RelationalSchemaProjection(BaseModel):
    layer: Literal["orm", "db-schema"]
    tables: list[RelationalTable] = Field(default_factory=list)


class ModelCorrelation(BaseModel):
    correlation_id: str
    kind: Literal["table", "column"]
    orm_element_id: str
    db_schema_element_id: str | None = None
    db_schema_context_id: str | None = None
    status: Literal["matched", "unresolved"]
    reason: str


AccessNodeKind = Literal[
    "api-endpoint",
    "java-type",
    "java-callable",
    "orm-type",
    "db-schema-table",
    "unresolved-table",
]
AccessMechanism = Literal[
    "orm", "mybatis", "jdbc", "cross-layer", "http", "call-graph", "codeql"
]
AccessOperation = Literal[
    "select", "insert", "update", "delete", "merge", "call", "ddl", "unknown"
]


class EndpointParameter(BaseModel):
    """One externally supplied endpoint value available for name matching."""

    parameter_id: str
    name: str
    location: Literal["path", "query", "header", "cookie", "form", "body", "unknown"]
    path: list[str] = Field(default_factory=list)
    required: bool = False
    schema_type: str | None = None
    # The Java formal parameter is the root CodeQL source. Scalar transport
    # parameters use it directly; body/bean leaves use a property read whose
    # receiver is tainted by this formal parameter.
    java_parameter_name: str | None = None
    java_parameter_index: int | None = None
    java_parameter_type: str | None = None
    java_parameter_line: int | None = None
    java_source_kind: Literal["direct", "property", "unresolved"] = "unresolved"


class EndpointParameterMatch(BaseModel):
    """A deterministic name connection to one reachable persistence element."""

    match_id: str
    endpoint_node_id: str
    parameter_id: str
    parameter_name: str
    parameter_location: str
    parameter_path: list[str] = Field(default_factory=list)
    model_element_id: str
    model_element_kind: ModelElementKind
    model_element_name: str
    owner_name: str
    layer: Literal["orm", "schema"]
    matched_alias: str
    match_kind: Literal[
        "exact", "normalized", "owner-qualified-id", "association-id"
    ]
    constraint_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    reason: str


class PersistenceTaintSink(BaseModel):
    """One source-level persistence call whose arguments are CodeQL sinks."""

    sink_id: str
    sink_kind: Literal["terminal-call", "orm-member-write"] = "terminal-call"
    terminal_node_id: str
    method_name: str
    owner_type: str | None = None
    member_name: str | None = None
    source: SourceLocation
    mechanism: AccessMechanism
    operations: list[AccessOperation] = Field(default_factory=list)
    target_model_element_ids: list[str] = Field(default_factory=list)
    resolution: Literal["resolved", "coarse", "unresolved"] = "coarse"
    reason: str


class EndpointParameterTaintFlow(BaseModel):
    """A CodeQL may-flow from one endpoint value to a persistence operand."""

    flow_id: str
    endpoint_node_id: str
    parameter_id: str
    parameter_name: str
    parameter_path: list[str] = Field(default_factory=list)
    sink_id: str
    terminal_node_id: str
    sink_slot_kind: Literal["argument", "field-write"] = "argument"
    sink_argument_index: int | None = None
    target_model_element_ids: list[str] = Field(default_factory=list)
    constraint_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    resolution: Literal["resolved", "coarse", "unresolved"]
    confidence: float = Field(ge=0.0, le=1.0)
    source: SourceLocation
    sink: SourceLocation
    reason: str


class TaintAnalysisFailure(BaseModel):
    stage: Literal["configuration", "database", "query", "decode", "import"]
    message: str


class CodeQLTaintAnalysis(BaseModel):
    """Serializable output of the optional CodeQL taint-flow phase."""

    query_version: str = "endpoint-persistence-reach-taint-v3"
    engine: str = "codeql"
    engine_version: str | None = None
    build_mode: Literal["none", "autobuild"] = "none"
    database_path: str | None = None
    source_facts: int = 0
    sink_facts: int = 0
    reachability_facts: int = 0
    reachability_edges: list[PersistenceAccessEdge] = Field(default_factory=list)
    sinks: list[PersistenceTaintSink] = Field(default_factory=list)
    flows: list[EndpointParameterTaintFlow] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    failures: list[TaintAnalysisFailure] = Field(default_factory=list)


class PersistenceAccessNode(BaseModel):
    """A join point between a Java call graph and a persistence model."""

    node_id: str
    kind: AccessNodeKind
    label: str
    # CLDK-style qualified type or ``qualified.Type#method(signature)``.  A
    # endpoint traversal joins its CLDK call graph to this value.
    symbol: str | None = None
    model_element_id: str | None = None
    mechanism: AccessMechanism | None = None
    sources: list[SourceLocation] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    parameters: list[EndpointParameter] = Field(default_factory=list)


class PersistenceAccessEdge(BaseModel):
    edge_id: str
    kind: Literal[
        "declares", "maps-to", "accesses", "implemented-by", "calls", "reaches"
    ]
    source_id: str
    target_id: str
    mechanism: AccessMechanism
    operations: list[AccessOperation] = Field(default_factory=list)
    resolution: Literal["matched", "unresolved", "not-applicable"]
    reason: str
    sources: list[SourceLocation] = Field(default_factory=list)
    # ``reaches`` edges store the shortest known endpoint-to-terminal path.
    # Other edge kinds leave these fields empty.
    depth: int | None = None
    path: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class PersistenceAccessGraph(BaseModel):
    """Deterministic terminals that endpoint/call-graph analysis can traverse."""

    nodes: list[PersistenceAccessNode] = Field(default_factory=list)
    edges: list[PersistenceAccessEdge] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class EndpointPersistenceTrace(BaseModel):
    endpoint_node_id: str
    access_node_ids: list[str] = Field(default_factory=list)
    orm_model_ids: list[str] = Field(default_factory=list)
    db_table_model_ids: list[str] = Field(default_factory=list)
    unresolved_table_node_ids: list[str] = Field(default_factory=list)
    constraint_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    parameter_match_ids: list[str] = Field(default_factory=list)
    parameter_taint_flow_ids: list[str] = Field(default_factory=list)
    paths: list[list[str]] = Field(default_factory=list)


class PersistenceModelBundle(BaseModel):
    model_version: str = MODEL_VERSION
    orm: OrmPersistenceModel = Field(default_factory=OrmPersistenceModel)
    db_schema: DBSchemaModel = Field(default_factory=DBSchemaModel)
    orm_projection: RelationalSchemaProjection = Field(
        default_factory=lambda: RelationalSchemaProjection(layer="orm")
    )
    db_schema_projection: RelationalSchemaProjection = Field(
        default_factory=lambda: RelationalSchemaProjection(layer="db-schema")
    )
    correlations: list[ModelCorrelation] = Field(default_factory=list)
    access_graph: PersistenceAccessGraph = Field(default_factory=PersistenceAccessGraph)
    endpoint_parameter_matches: list[EndpointParameterMatch] = Field(
        default_factory=list
    )
    taint_analysis: CodeQLTaintAnalysis | None = None


class PreparedPersistenceEvidence(BaseModel):
    schema_version: str = SCHEMA_VERSION
    prompt_version: str = PROMPT_VERSION
    project_path: str
    artifacts: list[EvidenceArtifact] = Field(default_factory=list)
    deterministic_constraints: list[ExtractedConstraint] = Field(default_factory=list)
    models: PersistenceModelBundle = Field(default_factory=PersistenceModelBundle)
    skipped_inputs: list[SkippedInput] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ConstraintFinding(ExtractedConstraint):
    finding_id: str
    sources: list[SourceLocation] = Field(default_factory=list)
    origin: Literal["deterministic", "llm"] = "llm"


class ConstraintGroup(BaseModel):
    group_id: str
    key: str
    finding_ids: list[str]
    status: Literal["single", "consistent", "conflict"]
    reason: str | None = None


class ExtractionFailure(BaseModel):
    artifact_id: str
    error_type: str
    message: str


class PersistenceConstraintReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    prompt_version: str = PROMPT_VERSION
    project_path: str
    evidence_file: str | None = None
    model: str
    artifacts_total: int
    artifacts_analyzed: int
    artifacts_llm_analyzed: int = 0
    deterministic_findings: int = 0
    llm_findings: int = 0
    findings: list[ConstraintFinding] = Field(default_factory=list)
    groups: list[ConstraintGroup] = Field(default_factory=list)
    failures: list[ExtractionFailure] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    skipped_inputs: list[SkippedInput] = Field(default_factory=list)
    models: PersistenceModelBundle = Field(default_factory=PersistenceModelBundle)
