"""Extend persistence access graphs with HTTP endpoint roots.

CLDK is used only for endpoint discovery and source/symbol metadata. Java
reachability from those roots to persistence terminals is evaluated by CodeQL
in :mod:`persispector.persistence.codeql_flow`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from persispector.annotations import parse_annotation
from persispector.operations import JavaApiOperation, JavaOperationIndex
from persispector.persistence.modeling import stable_model_id
from persispector.persistence.models import (
    EndpointParameter,
    EndpointParameterMatch,
    EndpointPersistenceTrace,
    PersistenceAccessEdge,
    PersistenceAccessGraph,
    PersistenceAccessNode,
    PersistenceModelBundle,
    SourceLocation,
)


@dataclass(frozen=True)
class _MethodRef:
    qualified_class: str
    callable: Any
    java_type: Any
    file_path: str

    @property
    def key(self) -> tuple[str, str]:
        return self.qualified_class, self.callable.signature

    @property
    def symbol(self) -> str:
        return f"{self.qualified_class}#{self.callable.signature}"


@dataclass(frozen=True)
class _PersistenceNameCandidate:
    model_element_id: str
    model_element_kind: str
    model_element_name: str
    owner_name: str
    owner_aliases: tuple[str, ...]
    layer: str
    aliases: tuple[str, ...]
    constraint_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...]


class _ProductionAnalysisView:
    """Hide conventional test sources from reused endpoint discovery."""

    def __init__(self, analysis: Any, is_test_path: Any) -> None:
        self._analysis = analysis
        self._is_test_path = is_test_path

    def __getattr__(self, name: str) -> Any:
        return getattr(self._analysis, name)

    def get_compilation_units(self) -> list[Any]:
        return [
            unit
            for unit in self._analysis.get_compilation_units()
            if not self._is_test_path(str(unit.file_path))
        ]

    def get_classes(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for qualified, java_type in self._analysis.get_classes().items():
            try:
                path = str(self._analysis.get_java_file(qualified) or "")
            except Exception:
                path = ""
            if not self._is_test_path(path):
                result[qualified] = java_type
        return result


class EndpointPersistenceGraphBuilder:
    """Add endpoint roots and implementation symbols for CodeQL to join."""

    def __init__(
        self,
        analysis: Any,
        project_path: str | Path,
        graph: PersistenceAccessGraph,
        *,
        max_depth: int = 8,
        max_methods_per_endpoint: int = 1_000,
        include_tests: bool = False,
    ) -> None:
        self.analysis = analysis
        self.project_path = Path(project_path).resolve()
        # Accepted for schema/CLI compatibility only. Reachability bounds now
        # belong to CodeQL rather than this endpoint-discovery phase.
        _ = max_depth, max_methods_per_endpoint
        self.include_tests = include_tests
        self.graph = graph.model_copy(deep=True)
        self.nodes = {item.node_id: item for item in self.graph.nodes}
        self.edges = {item.edge_id: item for item in self.graph.edges}
        self.classes: dict[str, Any] = analysis.get_classes()
        self.methods = self._index_methods()

    def build(self) -> PersistenceAccessGraph:
        endpoint_analysis = (
            self.analysis
            if self.include_tests
            else _ProductionAnalysisView(self.analysis, self._is_test_path)
        )
        operations = JavaOperationIndex(endpoint_analysis).operations
        for operation in operations:
            if not self.include_tests and self._is_test_path(operation.file_path):
                continue
            self._connect_endpoint(operation)
        self.graph.nodes = sorted(self.nodes.values(), key=lambda item: item.node_id)
        self.graph.edges = sorted(self.edges.values(), key=lambda item: item.edge_id)
        self.graph.warnings = sorted(set(self.graph.warnings))
        return self.graph

    def _connect_endpoint(self, operation: JavaApiOperation) -> None:
        endpoint_id = self._endpoint_node(operation)
        seeds: list[_MethodRef] = []
        endpoint_ref = self.methods.get(
            (operation.qualified_class, operation.method_signature)
        )
        if endpoint_ref:
            seeds.append(endpoint_ref)
        for qualified, signature in operation.locator_chain:
            locator = self.methods.get((qualified, signature))
            if locator:
                seeds.append(locator)
        seeds = list({item.key: item for item in seeds}.values())
        if not seeds:
            self.graph.warnings.append(
                f"Endpoint {operation.http_method.upper()} {operation.path} has no resolvable Java callable."
            )
            return

        for seed in seeds:
            callable_id = self._callable_node(seed)
            self._edge(
                "implemented-by",
                endpoint_id,
                callable_id,
                "http",
                "matched",
                "Endpoint route resolves to this Java callable.",
                self._method_sources(seed),
                depth=0,
                path=[endpoint_id, callable_id],
            )

    def _index_methods(self) -> dict[tuple[str, str], _MethodRef]:
        result: dict[tuple[str, str], _MethodRef] = {}
        for qualified, java_type in self.classes.items():
            try:
                file_path = str(self.analysis.get_java_file(qualified) or "")
            except Exception:
                file_path = ""
            if not self.include_tests and self._is_test_path(file_path):
                continue
            for java_callable in (java_type.callable_declarations or {}).values():
                if not java_callable.is_constructor:
                    ref = _MethodRef(qualified, java_callable, java_type, file_path)
                    result[ref.key] = ref
        return result

    def _endpoint_node(self, operation: JavaApiOperation) -> str:
        method = operation.http_method.upper()
        endpoint_id = stable_model_id(
            "accn", "endpoint", method, operation.path, operation.symbol
        )
        source = self._operation_source(operation)
        parameters = self._endpoint_parameters(operation, endpoint_id)
        self.nodes.setdefault(
            endpoint_id,
            PersistenceAccessNode(
                node_id=endpoint_id,
                kind="api-endpoint",
                label=f"{method} {operation.path}",
                symbol=operation.symbol,
                mechanism="http",
                sources=[source],
                metadata={
                    "http_method": method,
                    "path": operation.path,
                    "java_symbol": operation.symbol,
                },
                parameters=parameters,
            ),
        )
        return endpoint_id

    @staticmethod
    def _endpoint_parameters(
        operation: JavaApiOperation, endpoint_id: str
    ) -> list[EndpointParameter]:
        """Relate transport/body leaves to their Java formal source.

        A direct path/query/header value is represented by the formal itself.
        A request-body or bean property is represented by a property read whose
        receiver derives from the formal. CodeQL uses this distinction to avoid
        treating every leaf of a DTO as the same tainted value.
        """

        formals = list(operation.callable.parameters or [])
        annotated: list[tuple[int, Any, dict[str, Any]]] = []
        for index, formal in enumerate(formals):
            annotations = {
                item.name: item
                for item in (
                    parse_annotation(raw) for raw in formal.annotations or []
                )
            }
            annotated.append((index, formal, annotations))

        transport_annotations = {
            "PathVariable": "path",
            "PathParam": "path",
            "RequestParam": "query",
            "QueryParam": "query",
            "RequestHeader": "header",
            "HeaderParam": "header",
            "CookieValue": "cookie",
            "CookieParam": "cookie",
            "FormParam": "form",
        }

        def binding(detail: Any) -> tuple[int | None, Any | None, str]:
            # Explicit parameter annotations give the strongest connection.
            for index, formal, annotations in annotated:
                for annotation_name, location in transport_annotations.items():
                    annotation = annotations.get(annotation_name)
                    if annotation is None or location != detail.location:
                        continue
                    external_name = (
                        annotation.value("name", "value")
                        or formal.name
                        or "parameter"
                    )
                    if external_name == detail.name:
                        return index, formal, "direct"

            # Request body leaves and aggregate bean parameters originate at a
            # formal but become distinct only at their property reads.
            if detail.location in {"body", "form"}:
                for index, formal, annotations in annotated:
                    if annotations.keys() & {
                        "RequestBody", "BeanParam", "ModelAttribute"
                    }:
                        return index, formal, "property"

            for index, formal, annotations in annotated:
                if formal.name == detail.name:
                    kind = (
                        "property"
                        if annotations.keys() & {"BeanParam", "ModelAttribute"}
                        else "direct"
                    )
                    return index, formal, kind

            bean_formals = [
                (index, formal)
                for index, formal, annotations in annotated
                if annotations.keys() & {"BeanParam", "ModelAttribute"}
            ]
            if len(bean_formals) == 1:
                index, formal = bean_formals[0]
                return index, formal, "property"

            # JAX-RS permits an unannotated entity/body parameter.
            if detail.location == "body":
                unannotated = [
                    (index, formal)
                    for index, formal, annotations in annotated
                    if not annotations.keys() & set(transport_annotations)
                ]
                if len(unannotated) == 1:
                    index, formal = unannotated[0]
                    return index, formal, "property"

            if len(formals) == 1:
                return (
                    0,
                    formals[0],
                    "property" if len(detail.path) > 1 else "direct",
                )
            return None, None, "unresolved"

        result: list[EndpointParameter] = []
        for item in operation.parameter_details:
            index, formal, source_kind = binding(item)
            result.append(
                EndpointParameter(
                    parameter_id=stable_model_id(
                        "epp",
                        endpoint_id,
                        item.location,
                        ".".join(item.path),
                        item.name,
                    ),
                    name=item.name,
                    location=(
                        item.location
                        if item.location
                        in {"path", "query", "header", "cookie", "form", "body"}
                        else "unknown"
                    ),
                    path=list(item.path),
                    required=item.required,
                    schema_type=item.schema_type,
                    java_parameter_name=formal.name if formal else None,
                    java_parameter_index=index,
                    java_parameter_type=formal.type if formal else None,
                    java_parameter_line=_positive(formal.start_line) if formal else None,
                    java_source_kind=source_kind,
                )
            )
        return result

    def _callable_node(self, ref: _MethodRef) -> str:
        node_id = stable_model_id("accn", "call-graph-callable", ref.symbol)
        self.nodes.setdefault(
            node_id,
            PersistenceAccessNode(
                node_id=node_id,
                kind="java-callable",
                label=ref.symbol,
                symbol=ref.symbol,
                mechanism="call-graph",
                sources=self._method_sources(ref),
                metadata={"symbol_match": "exact", "role": "call-graph"},
            ),
        )
        return node_id

    def _edge(
        self,
        kind: str,
        source_id: str,
        target_id: str,
        mechanism: str,
        resolution: str,
        reason: str,
        sources: list[SourceLocation],
        *,
        depth: int | None = None,
        path: list[str] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> None:
        metadata = metadata or {}
        edge_id_parts = ["acce", kind, source_id, target_id, mechanism]
        if kind == "reaches" and sources:
            edge_id_parts.extend(
                [
                    sources[0].file_path,
                    str(sources[0].start_line or 0),
                    metadata.get("call_method", ""),
                ]
            )
        edge_id = stable_model_id(*edge_id_parts)
        candidate = PersistenceAccessEdge(
            edge_id=edge_id,
            kind=kind,
            source_id=source_id,
            target_id=target_id,
            mechanism=mechanism,
            resolution=resolution,
            reason=reason,
            sources=sources,
            depth=depth,
            path=path or [],
            metadata=metadata,
        )
        existing = self.edges.get(edge_id)
        if existing is None or (
            candidate.depth is not None
            and (existing.depth is None or candidate.depth < existing.depth)
        ):
            self.edges[edge_id] = candidate

    def _operation_source(self, operation: JavaApiOperation) -> SourceLocation:
        return SourceLocation(
            file_path=self._display_path(operation.file_path),
            start_line=_positive(operation.start_line),
            end_line=_positive(operation.end_line),
        )

    def _method_sources(self, ref: _MethodRef) -> list[SourceLocation]:
        return [
            SourceLocation(
                file_path=self._display_path(ref.file_path),
                start_line=_positive(ref.callable.start_line),
                end_line=_positive(ref.callable.end_line),
            )
        ]

    def _display_path(self, raw: str) -> str:
        if not raw:
            return "<unknown>"
        path = Path(raw)
        if not path.is_absolute():
            path = self.project_path / path
        try:
            return str(path.resolve().relative_to(self.project_path))
        except ValueError:
            return str(path.resolve())

    @staticmethod
    def _is_test_path(path: str) -> bool:
        normalized = "/" + path.replace("\\", "/").strip("/") + "/"
        return (
            "/src/test/" in normalized
            or "/src/it/" in normalized
            or normalized.rstrip("/").endswith("Test.java")
        )

def extend_access_graph_with_endpoints(
    analysis: Any,
    project_path: str | Path,
    graph: PersistenceAccessGraph,
    *,
    max_depth: int = 8,
    max_methods_per_endpoint: int = 1_000,
    include_tests: bool = False,
) -> PersistenceAccessGraph:
    return EndpointPersistenceGraphBuilder(
        analysis,
        project_path,
        graph,
        max_depth=max_depth,
        max_methods_per_endpoint=max_methods_per_endpoint,
        include_tests=include_tests,
    ).build()


def trace_endpoint_persistence(
    models: PersistenceModelBundle, endpoint_node_id: str
) -> EndpointPersistenceTrace:
    """Project one endpoint's graph paths onto models, constraints, and dependencies."""

    graph = models.access_graph
    nodes = {item.node_id: item for item in graph.nodes}
    reaches = [
        edge
        for edge in graph.edges
        if edge.kind == "reaches" and edge.source_id == endpoint_node_id
    ]
    accesses = {
        reach.target_id: [
            candidate
            for candidate in graph.edges
            if candidate.kind == "accesses"
            and candidate.source_id == reach.target_id
        ]
        for reach in reaches
    }
    maps_to: dict[str, list[PersistenceAccessEdge]] = {}
    for edge in graph.edges:
        if edge.kind == "maps-to":
            maps_to.setdefault(edge.source_id, []).append(edge)

    orm_ids: set[str] = set()
    db_ids: set[str] = set()
    unresolved_ids: set[str] = set()
    access_ids: set[str] = set()
    paths: list[list[str]] = []
    for reach in reaches:
        access_ids.add(reach.target_id)
        for access in accesses.get(reach.target_id, []):
            target = nodes.get(access.target_id)
            base_path = [*reach.path, access.target_id]
            if not target:
                continue
            if target.kind == "orm-type" and target.model_element_id:
                orm_ids.add(target.model_element_id)
                mapped = maps_to.get(target.node_id, [])
                if mapped:
                    for mapping in mapped:
                        mapped_target = nodes.get(mapping.target_id)
                        if mapped_target and mapped_target.model_element_id:
                            db_ids.add(mapped_target.model_element_id)
                        elif mapped_target and mapped_target.kind == "unresolved-table":
                            unresolved_ids.add(mapped_target.node_id)
                        paths.append([*base_path, mapping.target_id])
                else:
                    paths.append(base_path)
            elif target.kind == "db-schema-table" and target.model_element_id:
                db_ids.add(target.model_element_id)
                paths.append(base_path)
            elif target.kind == "unresolved-table":
                unresolved_ids.add(target.node_id)
                paths.append(base_path)

    constraint_ids: set[str] = set()
    dependency_ids: set[str] = set()
    for orm_type in models.orm.types:
        if orm_type.model_id not in orm_ids:
            continue
        for element in [orm_type, *orm_type.attributes, *orm_type.associations]:
            constraint_ids.update(element.constraint_ids)
            dependency_ids.update(element.dependency_ids)
    for table in models.db_schema.tables:
        if table.model_id not in db_ids:
            continue
        for element in [table, *table.columns]:
            constraint_ids.update(element.constraint_ids)
            dependency_ids.update(element.dependency_ids)

    parameter_match_ids = {
        item.match_id
        for item in models.endpoint_parameter_matches
        if item.endpoint_node_id == endpoint_node_id
    }
    parameter_taint_flow_ids = {
        item.flow_id
        for item in (
            models.taint_analysis.flows if models.taint_analysis else []
        )
        if item.endpoint_node_id == endpoint_node_id
    }

    return EndpointPersistenceTrace(
        endpoint_node_id=endpoint_node_id,
        access_node_ids=sorted(access_ids),
        orm_model_ids=sorted(orm_ids),
        db_table_model_ids=sorted(db_ids),
        unresolved_table_node_ids=sorted(unresolved_ids),
        constraint_ids=sorted(constraint_ids),
        dependency_ids=sorted(dependency_ids),
        parameter_match_ids=sorted(parameter_match_ids),
        parameter_taint_flow_ids=sorted(parameter_taint_flow_ids),
        paths=sorted(paths),
    )


def trace_all_endpoints(
    models: PersistenceModelBundle,
) -> list[EndpointPersistenceTrace]:
    return [
        trace_endpoint_persistence(models, node.node_id)
        for node in models.access_graph.nodes
        if node.kind == "api-endpoint"
    ]


def match_endpoint_parameters(
    models: PersistenceModelBundle,
) -> list[EndpointParameterMatch]:
    """Match endpoint names to reachable ORM members and DB columns.

    Matching is deliberately conservative: exact spelling, canonicalized
    camel/snake/kebab spelling, an owner-qualified primary-key form such as
    ``orderId`` -> ``orders.id``, or an association identifier such as
    ``customerId`` -> ``Order.customer``. No edit-distance or substring fuzzy
    matching is used.
    """

    result: list[EndpointParameterMatch] = []
    endpoints = [
        item for item in models.access_graph.nodes if item.kind == "api-endpoint"
    ]
    for endpoint in endpoints:
        trace = trace_endpoint_persistence(models, endpoint.node_id)
        candidates = _persistence_name_candidates(models, trace)
        for parameter in endpoint.parameters:
            for candidate in candidates:
                matched = _match_parameter_name(parameter, candidate)
                if not matched:
                    continue
                match_kind, parameter_alias, persistence_alias = matched
                match_id = stable_model_id(
                    "epm",
                    endpoint.node_id,
                    parameter.parameter_id,
                    candidate.model_element_id,
                    match_kind,
                )
                result.append(
                    EndpointParameterMatch(
                        match_id=match_id,
                        endpoint_node_id=endpoint.node_id,
                        parameter_id=parameter.parameter_id,
                        parameter_name=parameter.name,
                        parameter_location=parameter.location,
                        parameter_path=list(parameter.path),
                        model_element_id=candidate.model_element_id,
                        model_element_kind=candidate.model_element_kind,
                        model_element_name=candidate.model_element_name,
                        owner_name=candidate.owner_name,
                        layer=candidate.layer,
                        matched_alias=persistence_alias,
                        match_kind=match_kind,
                        constraint_ids=sorted(candidate.constraint_ids),
                        dependency_ids=sorted(candidate.dependency_ids),
                        reason=_parameter_match_reason(
                            match_kind,
                            parameter_alias,
                            persistence_alias,
                            candidate.owner_name,
                        ),
                    )
                )
    return sorted(result, key=lambda item: item.match_id)


def refresh_endpoint_parameter_matches(
    models: PersistenceModelBundle,
) -> PersistenceModelBundle:
    """Return a copy whose parameter matches reflect current model findings."""

    result = models.model_copy(deep=True)
    result.endpoint_parameter_matches = match_endpoint_parameters(result)
    return result


def _persistence_name_candidates(
    models: PersistenceModelBundle,
    trace: EndpointPersistenceTrace,
) -> list[_PersistenceNameCandidate]:
    result: list[_PersistenceNameCandidate] = []
    orm_ids = _expanded_orm_model_ids(models, set(trace.orm_model_ids))
    db_ids = set(trace.db_table_model_ids)
    for orm_type in models.orm.types:
        if orm_type.model_id not in orm_ids:
            continue
        owner_aliases = _unique_names(
            orm_type.qualified_name.rsplit(".", 1)[-1],
            orm_type.table.logical_name,
            orm_type.table.physical_name,
        )
        for attribute in orm_type.attributes:
            aliases = _unique_names(
                attribute.name,
                attribute.column.logical_name,
                attribute.column.physical_name,
            )
            result.append(
                _PersistenceNameCandidate(
                    model_element_id=attribute.model_id,
                    model_element_kind="orm-attribute",
                    model_element_name=attribute.name,
                    owner_name=orm_type.qualified_name,
                    owner_aliases=owner_aliases,
                    layer="orm",
                    aliases=aliases,
                    constraint_ids=tuple(attribute.constraint_ids),
                    dependency_ids=tuple(attribute.dependency_ids),
                )
            )
        for association in orm_type.associations:
            aliases = _unique_names(
                association.member,
                *(
                    value
                    for join in association.join_columns
                    for value in (
                        join.name.logical_name,
                        join.name.physical_name,
                    )
                ),
            )
            result.append(
                _PersistenceNameCandidate(
                    model_element_id=association.model_id,
                    model_element_kind="orm-association",
                    model_element_name=association.member,
                    owner_name=orm_type.qualified_name,
                    owner_aliases=owner_aliases,
                    layer="orm",
                    aliases=aliases,
                    constraint_ids=tuple(association.constraint_ids),
                    dependency_ids=tuple(association.dependency_ids),
                )
            )
    contexts = {
        item.context_id: item.label for item in models.db_schema.contexts
    }
    for table in models.db_schema.tables:
        if table.model_id not in db_ids:
            continue
        bare_owner_name = (
            table.name.physical_name or table.name.logical_name or table.model_id
        )
        context_label = contexts.get(
            table.schema_context_id, table.schema_context_id or "default"
        )
        owner_name = f"{bare_owner_name} [{context_label}]"
        owner_aliases = _unique_names(
            table.name.logical_name, table.name.physical_name
        )
        for column in table.columns:
            aliases = _unique_names(
                column.name.logical_name, column.name.physical_name
            )
            result.append(
                _PersistenceNameCandidate(
                    model_element_id=column.model_id,
                    model_element_kind="db-schema-column",
                    model_element_name=(
                        column.name.physical_name
                        or column.name.logical_name
                        or column.model_id
                    ),
                    owner_name=owner_name,
                    owner_aliases=owner_aliases,
                    layer="schema",
                    aliases=aliases,
                    constraint_ids=tuple(column.constraint_ids),
                    dependency_ids=tuple(column.dependency_ids),
                )
            )
    return result


def _expanded_orm_model_ids(
    models: PersistenceModelBundle, initial: set[str]
) -> set[str]:
    """Include mapped-superclass and embeddable members of reached entities."""

    result = set(initial)
    attribute_owners = {
        attribute.model_id: orm_type.model_id
        for orm_type in models.orm.types
        for attribute in orm_type.attributes
    }
    changed = True
    while changed:
        changed = False
        for dependency in models.orm.dependencies:
            target_id = dependency.target.model_id
            if not target_id or target_id in result:
                continue
            source_id = dependency.source.model_id
            source_reached = source_id in result
            if dependency.kind == "embedded":
                source_reached = attribute_owners.get(source_id or "") in result
            if dependency.kind not in {"inheritance", "embedded"} or not source_reached:
                continue
            result.add(target_id)
            changed = True
    return result


def _match_parameter_name(
    parameter: EndpointParameter,
    candidate: _PersistenceNameCandidate,
) -> tuple[str, str, str] | None:
    parameter_aliases = _endpoint_parameter_aliases(parameter)
    for parameter_alias in parameter_aliases:
        for candidate_alias in candidate.aliases:
            if parameter_alias == candidate_alias:
                return "exact", parameter_alias, candidate_alias
    for parameter_alias in parameter_aliases:
        normalized_parameter = _canonical_name(parameter_alias)
        if not normalized_parameter:
            continue
        for candidate_alias in candidate.aliases:
            normalized_candidate = _canonical_name(candidate_alias)
            if normalized_parameter == normalized_candidate:
                return "normalized", parameter_alias, candidate_alias
            if (
                candidate.model_element_kind == "orm-association"
                and normalized_parameter == normalized_candidate + "id"
            ):
                return "association-id", parameter_alias, candidate_alias
            if normalized_candidate != "id" or not normalized_parameter.endswith("id"):
                continue
            prefix = normalized_parameter[:-2]
            if prefix and prefix in _owner_name_variants(candidate.owner_aliases):
                return "owner-qualified-id", parameter_alias, candidate_alias
    return None


def _endpoint_parameter_aliases(parameter: EndpointParameter) -> tuple[str, ...]:
    values = [parameter.name]
    meaningful_path = [
        item for item in parameter.path if item not in {"body", "form"}
    ]
    if len(meaningful_path) >= 2:
        contextual = "".join(meaningful_path[-2:])
        # A nested leaf named only "id" is otherwise liable to match every
        # reachable primary key. Prefer its immediate object context, e.g.
        # body.customer.id -> customerId.
        if _canonical_name(parameter.name) == "id":
            values = [contextual]
        else:
            values.append(contextual)
    return _unique_names(*values)


def _owner_name_variants(values: tuple[str, ...]) -> set[str]:
    result: set[str] = set()
    for value in values:
        canonical = _canonical_name(value)
        if not canonical:
            continue
        result.add(canonical)
        if canonical.endswith("ies") and len(canonical) > 3:
            result.add(canonical[:-3] + "y")
        elif canonical.endswith("s") and not canonical.endswith("ss"):
            result.add(canonical[:-1])
        for suffix in ("entity", "record", "model", "dataobject"):
            if canonical.endswith(suffix) and len(canonical) > len(suffix):
                result.add(canonical[: -len(suffix)])
    return result


def _canonical_name(value: str) -> str:
    return "".join(character.casefold() for character in value if character.isalnum())


def _unique_names(*values: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _parameter_match_reason(
    match_kind: str,
    parameter_alias: str,
    persistence_alias: str,
    owner_name: str,
) -> str:
    if match_kind == "exact":
        return f"Endpoint and persistence names are exactly {parameter_alias!r}."
    if match_kind == "normalized":
        return (
            f"{parameter_alias!r} and {persistence_alias!r} are equal after "
            "case/separator normalization."
        )
    if match_kind == "association-id":
        return (
            f"{parameter_alias!r} names the identifier of association "
            f"{persistence_alias!r}."
        )
    return (
        f"{parameter_alias!r} is the owner-qualified identifier for "
        f"{owner_name}.{persistence_alias}."
    )


def _positive(value: int | None) -> int | None:
    return value if value is not None and value > 0 else None
