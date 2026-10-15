"""Human-readable Markdown rendering for persistence reports."""

from __future__ import annotations

from persispector.persistence.models import (
    ConstraintFinding,
    OrmType,
    PersistenceConstraintReport,
    RelationalTable,
    SourceLocation,
)
from persispector.persistence.endpoint_access import trace_all_endpoints


def render_persistence_markdown(report: PersistenceConstraintReport) -> str:
    """Render one analyzed report without consulting source files or a model."""

    conflicts = [group for group in report.groups if group.status == "conflict"]
    lines = [
        "# Persistence Constraint Report",
        "",
        f"- Project: `{_escape(report.project_path)}`",
        f"- Model: `{_escape(report.model)}`",
        f"- Prompt version: `{_escape(report.prompt_version)}`",
        f"- Evidence artifacts: {report.artifacts_analyzed}/{report.artifacts_total} analyzed",
        f"- Artifacts sent to model: {report.artifacts_llm_analyzed}",
        f"- Findings: {len(report.findings)}",
        f"- Deterministic findings: {report.deterministic_findings}",
        f"- LLM findings: {report.llm_findings}",
        f"- Conflicts: {len(conflicts)}",
        f"- Extraction failures: {len(report.failures)}",
    ]
    if report.evidence_file:
        lines.append(f"- Evidence file: `{_escape(report.evidence_file)}`")

    lines.extend(["", "## Persistence models", ""])
    _render_orm_model(lines, report)
    _render_db_schema_model(lines, report)
    _render_access_graph(lines, report)

    lines.extend(["", "## Constraints", ""])
    if not report.findings:
        lines.append("No declared persistence constraints were extracted.")
    else:
        by_layer: dict[str, list[ConstraintFinding]] = {
            "schema": [], "orm": [], "validation": []
        }
        for finding in report.findings:
            by_layer[finding.layer].append(finding)
        for layer, heading in (
            ("schema", "Database schema declarations"),
            ("orm", "ORM schema intent"),
            ("validation", "Application validation"),
        ):
            items = by_layer[layer]
            if not items:
                continue
            lines.extend(
                [
                    "",
                    f"### {heading}",
                    "",
                    "| Subject | Kind | Predicate | Model objects | Extraction | Source | Confidence |",
                    "| --- | --- | --- | --- | --- | --- | ---: |",
                ]
            )
            for finding in items:
                lines.append(
                    "| "
                    + " | ".join(
                        (
                            _escape(_subject(finding, report)),
                            _escape(finding.kind),
                            _escape(finding.predicate),
                            _escape(", ".join(finding.model_element_ids) or "—"),
                            finding.origin,
                            _escape(", ".join(_location(item) for item in finding.sources)),
                            f"{finding.confidence:.2f}",
                        )
                    )
                    + " |"
                )

    lines.extend(["", "## Model correlations", ""])
    if not report.models.correlations:
        lines.append(
            "No explicit ORM-to-DB-schema table or column correlations were available."
        )
    else:
        lines.extend(
            [
                "| Kind | ORM object | DB schema context | DB schema object | Status | Reason |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for correlation in report.models.correlations:
            lines.append(
                "| "
                + " | ".join(
                    (
                        correlation.kind,
                        f"`{correlation.orm_element_id}`",
                        (
                            f"`{_escape(_db_context_label(report, correlation.db_schema_context_id))}`"
                            if correlation.db_schema_context_id
                            else "—"
                        ),
                        (
                            f"`{correlation.db_schema_element_id}`"
                            if correlation.db_schema_element_id
                            else "—"
                        ),
                        correlation.status,
                        _escape(correlation.reason),
                    )
                )
                + " |"
            )

    lines.extend(["", "## Cross-layer consistency", ""])
    if not conflicts:
        lines.append("No incompatible declarations were identified among explicitly correlated subjects.")
    else:
        finding_by_id = {item.finding_id: item for item in report.findings}
        for group in conflicts:
            lines.append(f"- `{_escape(group.key)}`: {_escape(group.reason or 'conflicting declarations')}")
            for finding_id in group.finding_ids:
                finding = finding_by_id.get(finding_id)
                if finding:
                    lines.append(
                        f"  - `{finding.finding_id}` ({finding.layer}): "
                        f"{_escape(finding.predicate)}"
                    )

    if report.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {_escape(item)}" for item in report.warnings)
    if report.skipped_inputs:
        lines.extend(["", "## Skipped inputs", ""])
        lines.extend(
            f"- `{_escape(item.file_path)}`: {_escape(item.reason)}"
            for item in report.skipped_inputs
        )
    if report.failures:
        lines.extend(["", "## Extraction failures", ""])
        lines.extend(
            f"- `{failure.artifact_id}` ({failure.error_type}): {_escape(failure.message)}"
            for failure in report.failures
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "ORM findings describe schema-generation intent and validation findings describe "
            "application enforcement. This report does not verify which schema declarations were applied "
            "or inspect a live database.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_orm_model(
    lines: list[str], report: PersistenceConstraintReport
) -> None:
    orm = report.models.orm
    lines.extend(["### ORM model", ""])
    if not orm.types:
        lines.append("No mapped ORM types were modeled.")
        return
    lines.extend(
        [
            "| Type | Kind | Explicit table | Attributes | Associations | Constraints | Dependencies | Details |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for orm_type in orm.types:
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{_escape(orm_type.qualified_name)}`",
                    orm_type.declaration_kind,
                    (
                        f"`{_escape(orm_type.table.physical_name)}`"
                        if orm_type.table.explicit and orm_type.table.physical_name
                        else "—"
                    ),
                    str(len(orm_type.attributes)),
                    str(len(orm_type.associations)),
                    str(len(orm_type.constraint_ids)),
                    str(len(orm_type.dependency_ids)),
                    _escape(_orm_details(orm_type)),
                )
            )
            + " |"
        )


def _orm_details(orm_type: OrmType) -> str:
    """Return mapped-type details suitable for a single Markdown table cell."""

    mapped = [
        f"{item.name} → {item.column.physical_name}"
        for item in orm_type.attributes
        if item.column.explicit and item.column.physical_name
    ]
    associations = [
        f"{item.member} → {item.target_entity or '?'} ({item.relationship})"
        for item in orm_type.associations
    ]
    embedded = [
        f"{item.name} → {item.java_type} ({item.mapping_kind})"
        for item in orm_type.attributes
        if item.mapping_kind in {"embedded", "embedded-id"}
    ]
    details: list[str] = []
    if orm_type.parent_types:
        details.append(f"Extends: {', '.join(orm_type.parent_types)}")
    if mapped:
        details.append(f"Explicit columns: {', '.join(mapped)}")
    if embedded:
        details.append(f"Embedded values: {', '.join(embedded)}")
    if associations:
        details.append(f"Associations: {', '.join(associations)}")
    return "<br>".join(details) or "—"


def _render_db_schema_model(
    lines: list[str], report: PersistenceConstraintReport
) -> None:
    db_schema = report.models.db_schema
    lines.extend(["", "### DB schema model", ""])
    lines.append(f"Resolution status: `{db_schema.resolution_status}`.")
    lines.append(f"Schema contexts: {len(db_schema.contexts)}.")
    lines.append(f"Recorded schema operations: {len(db_schema.operations)}.")
    if not db_schema.tables:
        lines.append("No DB schema tables were modeled.")
        return
    lines.extend(
        [
            "",
            "| Context | Table | Columns | Constraints | Dependencies | Source |",
            "| --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    for table in db_schema.tables:
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{_escape(_db_context_label(report, table.schema_context_id))}`",
                    f"`{_escape(table.name.physical_name or '?')}`",
                    _escape(_columns(table)),
                    str(len(table.constraint_ids)),
                    str(len(table.dependency_ids)),
                    _escape(", ".join(_location(item) for item in table.sources)),
                )
            )
            + " |"
        )


def _render_access_graph(
    lines: list[str], report: PersistenceConstraintReport
) -> None:
    graph = report.models.access_graph
    endpoint_nodes = [item for item in graph.nodes if item.kind == "api-endpoint"]
    reach_edges = [item for item in graph.edges if item.kind == "reaches"]
    call_edges = [item for item in graph.edges if item.kind == "calls"]
    access_edges = [
        item for item in graph.edges if item.kind in {"accesses", "maps-to"}
    ]
    lines.extend(["", "### Persistence access graph", ""])
    lines.append(
        f"Recorded nodes: {len(graph.nodes)}; edges: {len(graph.edges)}; "
        f"persistence links: {len(access_edges)}; API endpoints: {len(endpoint_nodes)}; "
        f"call edges: {len(call_edges)}; endpoint reachability links: {len(reach_edges)}; "
        f"parameter matches: {len(report.models.endpoint_parameter_matches)}; "
        f"CodeQL taint flows: "
        f"{len(report.models.taint_analysis.flows) if report.models.taint_analysis else 0}."
    )
    if not access_edges:
        lines.append("No deterministic code-to-persistence access links were modeled.")
    else:
        nodes = {item.node_id: item for item in graph.nodes}
        lines.extend(
            [
                "",
                "| Source | Mechanism | Operations | Target | Resolution | Evidence |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for edge in access_edges:
            source = nodes.get(edge.source_id)
            target = nodes.get(edge.target_id)
            lines.append(
                "| "
                + " | ".join(
                    (
                        f"`{_escape(source.label if source else edge.source_id)}`",
                        edge.mechanism,
                        _escape(", ".join(edge.operations) or "—"),
                        f"`{_escape(target.label if target else edge.target_id)}`",
                        edge.resolution,
                        _escape(", ".join(_location(item) for item in edge.sources) or "—"),
                    )
                )
                + " |"
            )
    _render_endpoint_traces(lines, report)
    _render_endpoint_taint_flows(lines, report)
    _render_endpoint_parameter_matches(lines, report)
    if graph.warnings:
        lines.extend(["", "Access-discovery warnings:", ""])
        lines.extend(f"- {_escape(item)}" for item in graph.warnings)


def _render_endpoint_taint_flows(
    lines: list[str], report: PersistenceConstraintReport
) -> None:
    analysis = report.models.taint_analysis
    lines.extend(["", "#### Endpoint parameter taint flows (CodeQL reachability)", ""])
    if analysis is None:
        lines.append("CodeQL reachability and taint-flow analysis was not requested for this report.")
        return
    lines.append(
        f"Engine: `{_escape(analysis.engine)}`"
        + (
            f" `{_escape(analysis.engine_version)}`"
            if analysis.engine_version
            else ""
        )
        + f"; query: `{_escape(analysis.query_version)}`; "
        f"terminal facts: {analysis.reachability_facts}; "
        f"reachability links: {len(analysis.reachability_edges)}; "
        f"source facts: {analysis.source_facts}; sink facts: {analysis.sink_facts}."
    )
    if not analysis.flows:
        lines.append("No endpoint values were found to taint a persistence operand.")
    else:
        nodes = {item.node_id: item for item in report.models.access_graph.nodes}
        sinks = {item.sink_id: item for item in analysis.sinks}
        element_names = _model_element_names(report)
        lines.extend(
            [
                "",
                "| Endpoint | Parameter | Persistence terminal | Sink slot | Persistent targets | Resolution | Constraints | Dependencies | Evidence |",
                "| --- | --- | --- | ---: | --- | --- | ---: | ---: | --- |",
            ]
        )
        for flow in sorted(
            analysis.flows,
            key=lambda item: (
                nodes[item.endpoint_node_id].label
                if item.endpoint_node_id in nodes
                else item.endpoint_node_id,
                item.parameter_path,
                item.terminal_node_id,
                item.sink_argument_index if item.sink_argument_index is not None else -1,
            ),
        ):
            endpoint = nodes.get(flow.endpoint_node_id)
            terminal = nodes.get(flow.terminal_node_id)
            sink_fact = sinks.get(flow.sink_id)
            terminal_label = terminal.label if terminal else flow.terminal_node_id
            if sink_fact and sink_fact.method_name not in terminal_label:
                terminal_label = f"{terminal_label}#{sink_fact.method_name}"
            targets = [
                element_names.get(item, item)
                for item in flow.target_model_element_ids
            ]
            lines.append(
                "| "
                + " | ".join(
                    (
                        f"`{_escape(endpoint.label if endpoint else flow.endpoint_node_id)}`",
                        f"`{_escape('.'.join(flow.parameter_path) or flow.parameter_name)}`",
                        f"`{_escape(terminal_label)}`",
                        (
                            str(flow.sink_argument_index)
                            if flow.sink_slot_kind == "argument"
                            else "field write"
                        ),
                        _escape(", ".join(targets) or "—"),
                        flow.resolution,
                        str(len(flow.constraint_ids)),
                        str(len(flow.dependency_ids)),
                        _escape(f"{_location(flow.source)} → {_location(flow.sink)}"),
                    )
                )
                + " |"
            )
    if analysis.warnings:
        lines.extend(["", "Taint-analysis warnings:", ""])
        lines.extend(f"- {_escape(item)}" for item in analysis.warnings)
    if analysis.failures:
        lines.extend(["", "Taint-analysis failures:", ""])
        lines.extend(
            f"- `{failure.stage}`: {_escape(failure.message)}"
            for failure in analysis.failures
        )


def _model_element_names(report: PersistenceConstraintReport) -> dict[str, str]:
    result: dict[str, str] = {}
    for orm_type in report.models.orm.types:
        result[orm_type.model_id] = orm_type.qualified_name
        for attribute in orm_type.attributes:
            result[attribute.model_id] = f"{orm_type.qualified_name}.{attribute.name}"
        for association in orm_type.associations:
            result[association.model_id] = f"{orm_type.qualified_name}.{association.member}"
    for table in report.models.db_schema.tables:
        table_name = table.name.physical_name or table.name.logical_name or "?"
        context = _db_context_label(report, table.schema_context_id)
        result[table.model_id] = f"{table_name} [{context}]"
        for column in table.columns:
            column_name = column.name.physical_name or column.name.logical_name or "?"
            result[column.model_id] = f"{table_name}.{column_name} [{context}]"
    return result


def _db_context_label(
    report: PersistenceConstraintReport, context_id: str | None
) -> str:
    context = next(
        (
            item
            for item in report.models.db_schema.contexts
            if item.context_id == context_id
        ),
        None,
    )
    return context.label if context else context_id or "default"


def _render_endpoint_traces(
    lines: list[str], report: PersistenceConstraintReport
) -> None:
    graph = report.models.access_graph
    nodes = {item.node_id: item for item in graph.nodes}
    traces = trace_all_endpoints(report.models)
    lines.extend(["", "#### Endpoint persistence reachability", ""])
    if not traces:
        lines.append("No Spring MVC or JAX-RS endpoints were modeled.")
        return
    orm_names = {
        item.model_id: item.qualified_name for item in report.models.orm.types
    }
    table_names = {
        item.model_id: (
            f"{item.name.physical_name or '?'} "
            f"[{_db_context_label(report, item.schema_context_id)}]"
        )
        for item in report.models.db_schema.tables
    }
    reach_depths: dict[str, list[int]] = {}
    for edge in graph.edges:
        if edge.kind == "reaches" and edge.depth is not None:
            reach_depths.setdefault(edge.source_id, []).append(edge.depth)
    lines.extend(
        [
            "| Endpoint | Java implementation | Persistence terminals | ORM types | DB tables | Constraints | Dependencies | Reach depth | Source |",
            "| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for trace in traces:
        endpoint = nodes.get(trace.endpoint_node_id)
        if not endpoint:
            continue
        access_labels = [
            nodes[node_id].label
            for node_id in trace.access_node_ids
            if node_id in nodes
        ]
        db_labels = [table_names.get(item, item) for item in trace.db_table_model_ids]
        db_labels.extend(
            nodes[item].label
            for item in trace.unresolved_table_node_ids
            if item in nodes
        )
        depths = reach_depths.get(trace.endpoint_node_id, [])
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{_escape(endpoint.label)}`",
                    f"`{_escape(endpoint.metadata.get('java_symbol', endpoint.symbol or '—'))}`",
                    _escape(", ".join(access_labels) or "—"),
                    _escape(", ".join(orm_names.get(item, item) for item in trace.orm_model_ids) or "—"),
                    _escape(", ".join(db_labels) or "—"),
                    str(len(trace.constraint_ids)),
                    str(len(trace.dependency_ids)),
                    str(max(depths)) if depths else "—",
                    _escape(", ".join(_location(item) for item in endpoint.sources)),
                )
            )
            + " |"
        )


def _render_endpoint_parameter_matches(
    lines: list[str], report: PersistenceConstraintReport
) -> None:
    nodes = {item.node_id: item for item in report.models.access_graph.nodes}
    matches = report.models.endpoint_parameter_matches
    lines.extend(["", "#### Endpoint parameter matches", ""])
    if not matches:
        lines.append(
            "No endpoint parameter names matched reachable ORM attributes, "
            "associations, or DB columns."
        )
        return

    constraints = {
        item.constraint_id: item
        for item in [
            *report.models.orm.constraints,
            *report.models.db_schema.constraints,
        ]
    }
    dependencies = {
        item.dependency_id: item
        for item in [
            *report.models.orm.dependencies,
            *report.models.db_schema.dependencies,
        ]
    }
    lines.extend(
        [
            "| Endpoint | Parameter | Persistence element | Layer | Name match | Constraints | Dependencies |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    ordered = sorted(
        matches,
        key=lambda item: (
            nodes[item.endpoint_node_id].label
            if item.endpoint_node_id in nodes
            else item.endpoint_node_id,
            item.parameter_location,
            item.parameter_path,
            item.layer,
            item.owner_name,
            item.model_element_name,
        ),
    )
    for match in ordered:
        endpoint = nodes.get(match.endpoint_node_id)
        parameter_path = ".".join(match.parameter_path) or match.parameter_name
        constraint_labels = [
            f"{constraints[item].declaration.kind} (`{item}`)"
            for item in match.constraint_ids
            if item in constraints
        ]
        dependency_labels = [
            f"{dependencies[item].kind} (`{item}`)"
            for item in match.dependency_ids
            if item in dependencies
        ]
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{_escape(endpoint.label if endpoint else match.endpoint_node_id)}`",
                    f"`{_escape(parameter_path)}` ({_escape(match.parameter_location)})",
                    f"`{_escape(match.owner_name)}.{_escape(match.model_element_name)}`",
                    match.layer,
                    _escape(match.match_kind),
                    ", ".join(constraint_labels) or "—",
                    ", ".join(dependency_labels) or "—",
                )
            )
            + " |"
        )


def _columns(table: RelationalTable) -> str:
    if not table.columns:
        return "—"
    return ", ".join(
        f"{item.name.physical_name} {item.declared_type or ''}".rstrip()
        for item in table.columns
    )


def _subject(
    finding: ConstraintFinding, report: PersistenceConstraintReport
) -> str:
    subject = finding.subject
    owner = subject.table or subject.entity or "unresolved subject"
    if subject.schema_context_id:
        owner += f" [{_db_context_label(report, subject.schema_context_id)}]"
    members = subject.columns or subject.fields
    return f"{owner}({', '.join(members)})" if members else owner


def _location(location: SourceLocation) -> str:
    if location.start_line is None:
        return location.file_path
    if location.end_line and location.end_line != location.start_line:
        return f"{location.file_path}:{location.start_line}-{location.end_line}"
    return f"{location.file_path}:{location.start_line}"


def _escape(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
