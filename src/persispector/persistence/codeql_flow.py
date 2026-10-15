"""Optional CodeQL taint flow from HTTP inputs to persistence call operands.

Persispector discovers endpoint roots and persistence terminals first.  This
module turns those stable, source-located facts into a bounded CodeQL query,
runs only global taint tracking, and joins the results back to the persistence
model.  CodeQL proves the Java may-flow; existing ORM/SQL/MyBatis modeling
remains responsible for assigning persistent meaning to a terminal.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Sequence

from persispector.persistence.modeling import stable_model_id
from persispector.persistence.models import (
    CodeQLTaintAnalysis,
    EndpointParameterTaintFlow,
    PersistenceModelBundle,
    PersistenceAccessEdge,
    PersistenceTaintSink,
    PreparedPersistenceEvidence,
    SourceLocation,
    TaintAnalysisFailure,
)


QUERY_VERSION = "endpoint-persistence-reach-taint-v3"

_QUERY_PACK = """\
name: persispector/endpoint-persistence-taint
version: 0.0.0
dependencies:
  codeql/java-all: "*"
"""


@dataclass(frozen=True)
class _SourceFact:
    file_path: str
    method_line: int
    parameter_line: int
    parameter_index: int
    endpoint_id: str
    parameter_id: str
    source_kind: str
    property_name: str
    accessor_name: str


@dataclass(frozen=True)
class _EndpointReachFact:
    file_path: str
    method_line: int
    endpoint_id: str
    owner_type: str
    method_name: str


@dataclass(frozen=True)
class _ReachTerminalFact:
    terminal_id: str
    match_kind: str
    owner_type: str
    method_name: str
    file_path: str
    line: int


CommandRunner = Callable[
    [Sequence[str], Path | None, float], subprocess.CompletedProcess[str]
]


class CodeQLTaintAnalyzer:
    """Create/reuse a CodeQL database and evaluate the generated taint query."""

    def __init__(
        self,
        *,
        codeql_command: str | Path | None = None,
        database_dir: str | Path,
        work_dir: str | Path,
        build_mode: str = "none",
        timeout_seconds: float = 1_800,
        command_runner: CommandRunner | None = None,
    ) -> None:
        if build_mode not in {"none", "autobuild"}:
            raise ValueError("CodeQL build_mode must be 'none' or 'autobuild'.")
        self.codeql_command = str(
            codeql_command or os.getenv("CODEQL_COMMAND") or "codeql"
        )
        self.database_dir = Path(database_dir).resolve()
        self.work_dir = Path(work_dir).resolve()
        self.build_mode = build_mode
        self.timeout_seconds = max(1.0, timeout_seconds)
        self.command_runner = command_runner or _run_command

    def analyze(
        self, prepared: PreparedPersistenceEvidence
    ) -> CodeQLTaintAnalysis:
        endpoint_facts = _endpoint_reach_facts(prepared.models)
        terminal_facts = _reach_terminal_facts(prepared.models)
        result = CodeQLTaintAnalysis(
            query_version=QUERY_VERSION,
            build_mode=self.build_mode,
            database_path=str(self.database_dir),
            reachability_facts=len(terminal_facts),
        )
        if not endpoint_facts:
            result.warnings.append("No source-located CodeQL endpoint roots were available.")
            return result
        if not terminal_facts:
            result.warnings.append("No persistence terminal facts were available for CodeQL reachability.")
            return result

        executable = _resolve_command(self.codeql_command)
        if executable is None:
            result.failures.append(
                TaintAnalysisFailure(
                    stage="configuration",
                    message=(
                        f"CodeQL command {self.codeql_command!r} was not found. "
                        "Install the CodeQL CLI or pass --codeql-command."
                    ),
                )
            )
            return result

        result.engine_version = self._version(executable, result)
        if not self._ensure_database(executable, prepared, result):
            return result

        self.work_dir.mkdir(parents=True, exist_ok=True)
        try:
            with TemporaryDirectory(
                prefix="persispector-codeql-", dir=self.work_dir
            ) as temporary:
                temporary_path = Path(temporary)
                # A standalone query outside a QL pack has no dependency
                # context, so imports such as `java` and `DataFlow` cannot be
                # resolved even when the standard packs ship with the CLI.
                (temporary_path / "codeql-pack.yml").write_text(
                    _QUERY_PACK, encoding="utf-8"
                )
                reach_rows = self._evaluate_query(
                    executable,
                    temporary_path,
                    "EndpointPersistenceReachability",
                    render_codeql_reachability_query(
                        endpoint_facts, terminal_facts
                    ),
                )
                try:
                    reachability_edges, reach_warnings = _import_reachability_rows(
                        reach_rows, prepared.models, terminal_facts
                    )
                except Exception as error:
                    result.failures.append(
                        TaintAnalysisFailure(stage="import", message=str(error))
                    )
                    return result
                result.reachability_edges = reachability_edges
                result.warnings.extend(reach_warnings)

                reachable_models = prepared.models.model_copy(deep=True)
                reachable_models.access_graph.edges.extend(reachability_edges)
                from persispector.persistence.endpoint_access import (
                    refresh_endpoint_parameter_matches,
                )

                reachable_models = refresh_endpoint_parameter_matches(
                    reachable_models
                )
                source_facts = _source_facts(reachable_models)
                sinks = _taint_sinks(reachable_models)
                result.source_facts = len(source_facts)
                result.sink_facts = len(sinks)
                result.sinks = sinks
                unresolved = sum(
                    parameter.java_source_kind == "unresolved"
                    for node in reachable_models.access_graph.nodes
                    if node.kind == "api-endpoint"
                    and node.node_id in _taint_endpoint_ids(reachable_models)
                    for parameter in node.parameters
                )
                if unresolved:
                    result.warnings.append(
                        f"{unresolved} endpoint parameters had no Java formal source mapping."
                    )
                if not source_facts:
                    result.warnings.append(
                        "No CodeQL endpoint source facts were available after reachability."
                    )
                    return result
                if not sinks:
                    result.warnings.append(
                        "No source-located persistence sink facts were available after reachability."
                    )
                    return result
                rows = self._evaluate_query(
                    executable,
                    temporary_path,
                    "EndpointPersistenceTaint",
                    render_codeql_taint_query(source_facts, sinks),
                )
        except _CodeQLStageError as error:
            result.failures.append(
                TaintAnalysisFailure(stage=error.stage, message=str(error))
            )
            return result
        except (OSError, UnicodeError, csv.Error) as error:
            result.failures.append(
                TaintAnalysisFailure(stage="decode", message=str(error))
            )
            return result

        try:
            result.flows, import_warnings = _import_rows(
                rows, reachable_models, sinks
            )
            result.warnings.extend(import_warnings)
        except Exception as error:  # preserve a partial report on schema drift
            result.failures.append(
                TaintAnalysisFailure(stage="import", message=str(error))
            )
        return result

    def _evaluate_query(
        self,
        executable: str,
        directory: Path,
        name: str,
        query: str,
    ) -> list[list[str]]:
        query_path = directory / f"{name}.ql"
        bqrs_path = directory / f"{name}.bqrs"
        csv_path = directory / f"{name}.csv"
        query_path.write_text(query, encoding="utf-8")
        self._run(
            [
                executable,
                "query",
                "run",
                str(query_path),
                f"--database={self.database_dir}",
                f"--output={bqrs_path}",
            ],
            stage="query",
        )
        self._run(
            [
                executable,
                "bqrs",
                "decode",
                "--format=csv",
                "--no-titles",
                f"--output={csv_path}",
                "--",
                str(bqrs_path),
            ],
            stage="decode",
        )
        return list(csv.reader(csv_path.read_text(encoding="utf-8").splitlines()))

    def _version(
        self, executable: str, result: CodeQLTaintAnalysis
    ) -> str | None:
        try:
            completed = self.command_runner(
                [executable, "version", "--format=json"],
                None,
                min(self.timeout_seconds, 60.0),
            )
            payload = json.loads(completed.stdout or "{}")
            return str(payload.get("version") or "") or None
        except Exception as error:
            result.warnings.append(f"Could not determine CodeQL version: {error}")
            return None

    def _ensure_database(
        self,
        executable: str,
        prepared: PreparedPersistenceEvidence,
        result: CodeQLTaintAnalysis,
    ) -> bool:
        marker = self.database_dir / "codeql-database.yml"
        metadata_path = self.database_dir / "persispector-codeql.json"
        project = Path(prepared.project_path).resolve()
        fingerprint = _project_fingerprint(project)
        if marker.is_file():
            if metadata_path.is_file():
                try:
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    result.failures.append(
                        TaintAnalysisFailure(
                            stage="database",
                            message=f"Could not read CodeQL cache metadata: {error}",
                        )
                    )
                    return False
                if (
                    metadata.get("project_path") != str(project)
                    or metadata.get("project_fingerprint") != fingerprint
                    or metadata.get("build_mode") != self.build_mode
                ):
                    result.failures.append(
                        TaintAnalysisFailure(
                            stage="database",
                            message=(
                                f"CodeQL database {self.database_dir} is stale or belongs "
                                "to another project. Use a new --database-dir; Persispector "
                                "will not overwrite it automatically."
                            ),
                        )
                    )
                    return False
            else:
                result.warnings.append(
                    "Reusing a CodeQL database without Persispector cache metadata; "
                    "project freshness could not be verified."
                )
            return True
        if self.database_dir.exists() and any(self.database_dir.iterdir()):
            result.failures.append(
                TaintAnalysisFailure(
                    stage="database",
                    message=(
                        f"CodeQL database directory {self.database_dir} is nonempty "
                        "but has no codeql-database.yml marker."
                    ),
                )
            )
            return False
        self.database_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._run(
                [
                    executable,
                    "database",
                    "create",
                    str(self.database_dir),
                    "--language=java-kotlin",
                    f"--source-root={project}",
                    f"--build-mode={self.build_mode}",
                ],
                stage="database",
            )
        except _CodeQLStageError as error:
            result.failures.append(
                TaintAnalysisFailure(stage="database", message=str(error))
            )
            return False
        if marker.is_file() or self.database_dir.exists():
            metadata_path.write_text(
                json.dumps(
                    {
                        "project_path": str(project),
                        "project_fingerprint": fingerprint,
                        "build_mode": self.build_mode,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return True
        return False

    def _run(self, command: Sequence[str], *, stage: str) -> None:
        try:
            self.command_runner(command, None, self.timeout_seconds)
        except subprocess.TimeoutExpired as error:
            raise _CodeQLStageError(
                stage, f"CodeQL {stage} timed out after {self.timeout_seconds:g}s."
            ) from error
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or error.stdout or str(error)).strip()
            raise _CodeQLStageError(stage, detail) from error
        except OSError as error:
            raise _CodeQLStageError(stage, str(error)) from error


class _CodeQLStageError(RuntimeError):
    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage


def apply_codeql_taint_analysis(
    prepared: PreparedPersistenceEvidence, analysis: CodeQLTaintAnalysis
) -> PreparedPersistenceEvidence:
    """Return an evidence copy with taint results available to analysis/rendering."""

    result = prepared.model_copy(deep=True)
    result.models.access_graph.edges = [
        edge
        for edge in result.models.access_graph.edges
        if edge.kind != "reaches"
    ]
    result.models.access_graph.edges.extend(analysis.reachability_edges)
    result.models.access_graph.edges.sort(key=lambda item: item.edge_id)
    result.models.taint_analysis = analysis
    from persispector.persistence.endpoint_access import (
        refresh_endpoint_parameter_matches,
    )

    result.models = refresh_endpoint_parameter_matches(result.models)
    result.warnings.extend(
        f"CodeQL {failure.stage} failure: {failure.message}"
        for failure in analysis.failures
    )
    return result


def refresh_codeql_taint_links(
    models: PersistenceModelBundle,
) -> PersistenceModelBundle:
    """Refresh column/constraint attachments after report findings are modeled."""

    if models.taint_analysis is None:
        return models
    result = models.model_copy(deep=True)
    analysis = result.taint_analysis
    if analysis is None:
        return result
    sinks = {item.sink_id: item for item in analysis.sinks}
    parent_by_element = _element_parents(result)
    attachments = _element_attachments(result)
    matches: dict[tuple[str, str], list[object]] = {}
    for item in result.endpoint_parameter_matches:
        matches.setdefault((item.endpoint_node_id, item.parameter_id), []).append(item)
    for flow in analysis.flows:
        sink = sinks.get(flow.sink_id)
        if sink is None:
            continue
        base_targets = set(sink.target_model_element_ids)
        related = [
            item
            for item in matches.get((flow.endpoint_node_id, flow.parameter_id), [])
            if parent_by_element.get(item.model_element_id) in base_targets
            or item.model_element_id in base_targets
        ]
        refined = sorted({item.model_element_id for item in related})
        flow.target_model_element_ids = refined or sorted(base_targets)
        flow.constraint_ids = sorted(
            {value for item in related for value in item.constraint_ids}
            | {
                value
                for target in flow.target_model_element_ids
                for value in attachments.get(target, ((), ()))[0]
            }
        )
        flow.dependency_ids = sorted(
            {value for item in related for value in item.dependency_ids}
            | {
                value
                for target in flow.target_model_element_ids
                for value in attachments.get(target, ((), ()))[1]
            }
        )
        flow.resolution = (
            "resolved"
            if refined or sink.resolution == "resolved"
            else "coarse" if base_targets else "unresolved"
        )
        flow.confidence = 0.9 if flow.resolution == "resolved" else 0.65
    return result


def _endpoint_reach_facts(
    models: PersistenceModelBundle,
) -> list[_EndpointReachFact]:
    result: set[_EndpointReachFact] = set()
    for endpoint in models.access_graph.nodes:
        if endpoint.kind != "api-endpoint":
            continue
        for source in endpoint.sources:
            if source.start_line and source.file_path != "<unknown>":
                owner_type, separator, declaration = (endpoint.symbol or "").partition("#")
                method_name = declaration.split("(", 1)[0] if separator else ""
                result.add(
                    _EndpointReachFact(
                        file_path=_normalize_path(source.file_path),
                        method_line=source.start_line,
                        endpoint_id=endpoint.node_id,
                        owner_type=owner_type,
                        method_name=method_name,
                    )
                )
    return sorted(result, key=lambda item: tuple(item.__dict__.values()))


def _reach_terminal_facts(
    models: PersistenceModelBundle,
) -> list[_ReachTerminalFact]:
    graph = models.access_graph
    nodes = {item.node_id: item for item in graph.nodes}
    accesses: dict[str, list[object]] = {}
    for edge in graph.edges:
        if edge.kind == "accesses":
            accesses.setdefault(edge.source_id, []).append(edge)

    result: set[_ReachTerminalFact] = set()
    for terminal_id, terminal_accesses in accesses.items():
        terminal = nodes.get(terminal_id)
        if terminal is None or not terminal.symbol:
            continue
        if terminal.kind == "java-type":
            result.add(
                _ReachTerminalFact(
                    terminal_id=terminal_id,
                    match_kind="type",
                    owner_type=terminal.symbol,
                    method_name="",
                    file_path="",
                    line=0,
                )
            )
        elif terminal.kind == "java-callable":
            owner_type, separator, declaration = terminal.symbol.partition("#")
            method_name = declaration.split("(", 1)[0].strip() if separator else ""
            if owner_type and method_name:
                result.add(
                    _ReachTerminalFact(
                        terminal_id=terminal_id,
                        match_kind="method",
                        owner_type=owner_type,
                        method_name=method_name,
                        file_path="",
                        line=0,
                    )
                )

        # Direct JDBC/native-ORM accesses are represented by the enclosing
        # callable node, but the access edge cites the actual database call.
        # Matching that location lets an endpoint implemented by the same
        # callable reach the terminal without manufacturing a self-call.
        for edge in terminal_accesses:
            if not (
                edge.reason.startswith("Constant SQL is passed to ")
                or " explicitly references an ORM type" in edge.reason
            ):
                continue
            for source in edge.sources:
                if (
                    source.start_line
                    and source.file_path != "<unknown>"
                    and source.file_path.lower().endswith(".java")
                ):
                    result.add(
                        _ReachTerminalFact(
                            terminal_id=terminal_id,
                            match_kind="location",
                            owner_type="",
                            method_name="",
                            file_path=_normalize_path(source.file_path),
                            line=source.start_line,
                        )
                    )
    return sorted(result, key=lambda item: tuple(item.__dict__.values()))


def render_codeql_reachability_query(
    endpoints: Sequence[_EndpointReachFact],
    terminals: Sequence[_ReachTerminalFact],
) -> str:
    """Render the CodeQL-only endpoint-to-persistence call relation."""

    endpoint_rows = "\n    or\n    ".join(
        "(" + " and ".join(
            (
                f"filePath = {_ql_string(item.file_path)}",
                f"methodLine = {item.method_line}",
                f"endpointId = {_ql_string(item.endpoint_id)}",
                f"ownerType = {_ql_string(item.owner_type)}",
                f"methodName = {_ql_string(item.method_name)}",
            )
        ) + ")"
        for item in endpoints
    )
    terminal_rows = "\n    or\n    ".join(
        "(" + " and ".join(
            (
                f"terminalId = {_ql_string(item.terminal_id)}",
                f"matchKind = {_ql_string(item.match_kind)}",
                f"ownerType = {_ql_string(item.owner_type)}",
                f"methodName = {_ql_string(item.method_name)}",
                f"filePath = {_ql_string(item.file_path)}",
                f"line = {item.line}",
            )
        ) + ")"
        for item in terminals
    )
    return (
        _REACHABILITY_QUERY_TEMPLATE.replace(
            "__ENDPOINT_ROWS__",
            endpoint_rows
            or (
                'filePath = "" and methodLine = 0 and endpointId = "" and '
                'ownerType = "" and methodName = "" and 1 = 0'
            ),
        ).replace(
            "__TERMINAL_ROWS__",
            terminal_rows
            or (
                'terminalId = "" and matchKind = "" and ownerType = "" and '
                'methodName = "" and filePath = "" and line = 0 and 1 = 0'
            ),
        )
    )


def _import_reachability_rows(
    rows: Sequence[Sequence[str]],
    models: PersistenceModelBundle,
    facts: Sequence[_ReachTerminalFact],
) -> tuple[list[PersistenceAccessEdge], list[str]]:
    endpoints = {
        item.node_id
        for item in models.access_graph.nodes
        if item.kind == "api-endpoint"
    }
    terminals = {item.terminal_id for item in facts}
    warnings: list[str] = []
    result: dict[str, PersistenceAccessEdge] = {}
    for number, row in enumerate(rows, start=1):
        if len(row) != 7:
            warnings.append(
                f"Ignored CodeQL reachability row {number}: expected 7 columns, got {len(row)}."
            )
            continue
        (
            endpoint_id,
            terminal_id,
            call_file,
            call_line_raw,
            call_column_raw,
            call_method,
            endpoint_line_raw,
        ) = row
        if endpoint_id not in endpoints or terminal_id not in terminals:
            warnings.append(
                f"Ignored CodeQL reachability row {number}: unknown endpoint or terminal ID."
            )
            continue
        try:
            call_line = int(call_line_raw)
            int(call_column_raw)
            int(endpoint_line_raw)
        except ValueError:
            warnings.append(
                f"Ignored CodeQL reachability row {number}: non-integer source location."
            )
            continue
        source = SourceLocation(
            file_path=_normalize_path(call_file), start_line=call_line
        )
        edge_id = stable_model_id(
            "acce",
            "reaches",
            endpoint_id,
            terminal_id,
            "codeql",
            source.file_path,
            str(call_line),
            call_method,
        )
        result[edge_id] = PersistenceAccessEdge(
            edge_id=edge_id,
            kind="reaches",
            source_id=endpoint_id,
            target_id=terminal_id,
            mechanism="codeql",
            resolution="matched",
            reason=(
                "CodeQL call-graph reachability connects the endpoint callable "
                "to this persistence terminal callsite."
            ),
            sources=[source],
            path=[endpoint_id, terminal_id],
            metadata={
                "call_method": call_method,
                "reachability_engine": "codeql",
            },
        )
    return sorted(result.values(), key=lambda item: item.edge_id), warnings


def render_codeql_taint_query(
    source_facts: Sequence[_SourceFact], sinks: Sequence[PersistenceTaintSink]
) -> str:
    """Render a self-contained query; source text never becomes QL syntax."""

    source_rows = "\n    or\n    ".join(
        "(" + " and ".join(
            (
                f"filePath = {_ql_string(item.file_path)}",
                f"methodLine = {item.method_line}",
                f"parameterLine = {item.parameter_line}",
                f"parameterIndex = {item.parameter_index}",
                f"endpointId = {_ql_string(item.endpoint_id)}",
                f"parameterId = {_ql_string(item.parameter_id)}",
                f"sourceKind = {_ql_string(item.source_kind)}",
                f"propertyName = {_ql_string(item.property_name)}",
                f"accessorName = {_ql_string(item.accessor_name)}",
            )
        ) + ")"
        for item in source_facts
    )
    sink_rows = "\n    or\n    ".join(
        "(" + " and ".join(
            (
                f"filePath = {_ql_string(item.source.file_path)}",
                f"line = {item.source.start_line or 0}",
                f"methodName = {_ql_string(item.method_name)}",
                f"sinkId = {_ql_string(item.sink_id)}",
                f"terminalId = {_ql_string(item.terminal_node_id)}",
            )
        ) + ")"
        for item in sinks
        if item.sink_kind == "terminal-call"
    )
    orm_sink_rows = "\n    or\n    ".join(
        "(" + " and ".join(
            (
                f"ownerType = {_ql_string(item.owner_type or '')}",
                f"setterName = {_ql_string(item.method_name)}",
                f"memberName = {_ql_string(item.member_name or '')}",
                f"sinkId = {_ql_string(item.sink_id)}",
                f"terminalId = {_ql_string(item.terminal_node_id)}",
            )
        ) + ")"
        for item in sinks
        if item.sink_kind == "orm-member-write"
    )
    return (
        _QUERY_TEMPLATE.replace(
            "__SOURCE_ROWS__",
            source_rows
            or (
                'filePath = "" and methodLine = 0 and parameterLine = 0 and '
                'parameterIndex = 0 and endpointId = "" and parameterId = "" and '
                'sourceKind = "" and propertyName = "" and accessorName = "" and 1 = 0'
            ),
        )
        .replace(
            "__SINK_ROWS__",
            sink_rows
            or (
                'filePath = "" and line = 0 and methodName = "" and '
                'sinkId = "" and terminalId = "" and 1 = 0'
            ),
        )
        .replace(
            "__ORM_SINK_ROWS__",
            orm_sink_rows
            or (
                'ownerType = "" and setterName = "" and memberName = "" and '
                'sinkId = "" and terminalId = "" and 1 = 0'
            ),
        )
    )


def _source_facts(models: PersistenceModelBundle) -> list[_SourceFact]:
    result: list[_SourceFact] = []
    # A terminal elsewhere in the application does not make every HTTP
    # parameter a useful global source. Bound CodeQL to endpoints for which
    # the access graph found at least one reachable persistence terminal.
    taint_endpoint_ids = _taint_endpoint_ids(models)
    for endpoint in models.access_graph.nodes:
        if (
            endpoint.kind != "api-endpoint"
            or endpoint.node_id not in taint_endpoint_ids
            or not endpoint.sources
        ):
            continue
        source = endpoint.sources[0]
        if not source.start_line or source.file_path == "<unknown>":
            continue
        for parameter in endpoint.parameters:
            if (
                parameter.java_source_kind == "unresolved"
                or parameter.java_parameter_index is None
            ):
                continue
            if parameter.java_source_kind == "direct":
                accessors = [("", "")]
            else:
                property_name = next(
                    (
                        item
                        for item in reversed(parameter.path)
                        if item not in {"body", "form"}
                    ),
                    parameter.name,
                )
                capitalized = property_name[:1].upper() + property_name[1:]
                accessors = [
                    (property_name, property_name),
                    (property_name, f"get{capitalized}"),
                    (property_name, f"is{capitalized}"),
                ]
            for property_name, accessor in accessors:
                result.append(
                    _SourceFact(
                        file_path=_normalize_path(source.file_path),
                        method_line=source.start_line,
                        parameter_line=parameter.java_parameter_line or source.start_line,
                        parameter_index=parameter.java_parameter_index,
                        endpoint_id=endpoint.node_id,
                        parameter_id=parameter.parameter_id,
                        source_kind=parameter.java_source_kind,
                        property_name=property_name,
                        accessor_name=accessor,
                    )
                )
    return sorted(set(result), key=lambda item: tuple(item.__dict__.values()))


def _taint_endpoint_ids(models: PersistenceModelBundle) -> set[str]:
    return {
        edge.source_id
        for edge in models.access_graph.edges
        if edge.kind == "reaches"
    }


def _taint_sinks(models: PersistenceModelBundle) -> list[PersistenceTaintSink]:
    graph = models.access_graph
    nodes = {item.node_id: item for item in graph.nodes}
    accesses: dict[str, list[object]] = {}
    for edge in graph.edges:
        if edge.kind == "accesses":
            accesses.setdefault(edge.source_id, []).append(edge)

    result: dict[str, PersistenceTaintSink] = {}
    for reach in graph.edges:
        if reach.kind != "reaches":
            continue
        terminal = nodes.get(reach.target_id)
        if not terminal or not terminal.symbol:
            continue
        method_name = reach.metadata.get("call_method") or _symbol_method_name(
            terminal.symbol
        )
        if not method_name:
            continue
        terminal_accesses = accesses.get(terminal.node_id, [])
        target_ids = sorted(
            {
                nodes[edge.target_id].model_element_id
                for edge in terminal_accesses
                if edge.target_id in nodes
                and nodes[edge.target_id].model_element_id is not None
            }
        )
        operations = sorted(
            {operation for edge in terminal_accesses for operation in edge.operations}
        )
        mechanism = (
            terminal.mechanism
            if terminal.mechanism in {"orm", "mybatis", "jdbc"}
            else next(
                (
                    edge.mechanism
                    for edge in terminal_accesses
                    if edge.mechanism in {"orm", "mybatis", "jdbc"}
                ),
                "orm",
            )
        )
        for source in reach.sources:
            if not source.start_line or source.file_path == "<unknown>":
                continue
            normalized_source = source.model_copy(
                update={"file_path": _normalize_path(source.file_path)}
            )
            sink_id = stable_model_id(
                "taintsink",
                terminal.node_id,
                normalized_source.file_path,
                str(normalized_source.start_line),
                method_name,
            )
            result[sink_id] = PersistenceTaintSink(
                sink_id=sink_id,
                terminal_node_id=terminal.node_id,
                method_name=method_name,
                source=normalized_source,
                mechanism=mechanism,
                operations=operations or ["unknown"],
                target_model_element_ids=target_ids,
                resolution="coarse" if target_ids else "unresolved",
                reason=(
                    "CodeQL reachability identifies this source-level call "
                    "as a persistence terminal; every explicit call argument is a "
                    "candidate CodeQL taint sink."
                ),
            )
    # Entity setters provide a more precise sink than save(entity): the setter
    # argument is deterministically bound to one ORM member before CodeQL runs.
    for orm_type in models.orm.types:
        terminal_id = stable_model_id("accn", "model", orm_type.model_id)
        for member in [*orm_type.attributes, *orm_type.associations]:
            member_name = member.name if hasattr(member, "name") else member.member
            setter_name = "set" + member_name[:1].upper() + member_name[1:]
            sink_id = stable_model_id("taintsink", "orm-member-write", member.model_id)
            member_sources = list(member.sources or orm_type.sources)
            result[sink_id] = PersistenceTaintSink(
                sink_id=sink_id,
                sink_kind="orm-member-write",
                terminal_node_id=terminal_id,
                method_name=setter_name,
                owner_type=orm_type.qualified_name,
                member_name=member_name,
                source=(
                    member_sources[0]
                    if member_sources
                    else SourceLocation(file_path="<unknown>")
                ),
                mechanism="orm",
                operations=["unknown"],
                target_model_element_ids=[member.model_id],
                resolution="resolved",
                reason=(
                    f"{orm_type.qualified_name}.{setter_name}(...) writes the "
                    f"explicitly modeled ORM member {member_name}."
                ),
            )
    return sorted(result.values(), key=lambda item: item.sink_id)


def _import_rows(
    rows: Sequence[Sequence[str]],
    models: PersistenceModelBundle,
    sinks: Sequence[PersistenceTaintSink],
) -> tuple[list[EndpointParameterTaintFlow], list[str]]:
    endpoints = {
        item.node_id: item
        for item in models.access_graph.nodes
        if item.kind == "api-endpoint"
    }
    parameters = {
        (endpoint.node_id, parameter.parameter_id): parameter
        for endpoint in endpoints.values()
        for parameter in endpoint.parameters
    }
    sinks_by_id = {item.sink_id: item for item in sinks}
    matches = {
        (item.endpoint_node_id, item.parameter_id): []
        for item in models.endpoint_parameter_matches
    }
    for item in models.endpoint_parameter_matches:
        matches.setdefault((item.endpoint_node_id, item.parameter_id), []).append(item)
    parent_by_element = _element_parents(models)
    attachments = _element_attachments(models)

    warnings: list[str] = []
    result: dict[str, EndpointParameterTaintFlow] = {}
    for number, row in enumerate(rows, start=1):
        if len(row) != 12:
            warnings.append(
                f"Ignored CodeQL result row {number}: expected 12 columns, got {len(row)}."
            )
            continue
        (
            endpoint_id,
            parameter_id,
            sink_id,
            terminal_id,
            slot_kind,
            argument_index_raw,
            sink_file,
            sink_line_raw,
            sink_column_raw,
            source_file,
            source_line_raw,
            source_column_raw,
        ) = row
        parameter = parameters.get((endpoint_id, parameter_id))
        sink_fact = sinks_by_id.get(sink_id)
        if parameter is None or sink_fact is None:
            warnings.append(
                f"Ignored CodeQL result row {number}: unknown source or sink ID."
            )
            continue
        if terminal_id != sink_fact.terminal_node_id:
            warnings.append(
                f"Ignored CodeQL result row {number}: sink and terminal IDs do not "
                "match the prepared evidence."
            )
            continue
        try:
            argument_index_value = int(argument_index_raw)
            sink_line = int(sink_line_raw)
            sink_column = int(sink_column_raw)
            source_line = int(source_line_raw)
            source_column = int(source_column_raw)
        except ValueError:
            warnings.append(
                f"Ignored CodeQL result row {number}: non-integer location or argument."
            )
            continue
        if slot_kind not in {"argument", "field-write"}:
            warnings.append(
                f"Ignored CodeQL result row {number}: unknown sink slot kind {slot_kind!r}."
            )
            continue
        argument_index = argument_index_value if slot_kind == "argument" else None

        base_targets = set(sink_fact.target_model_element_ids)
        related_matches = [
            item
            for item in matches.get((endpoint_id, parameter_id), [])
            if parent_by_element.get(item.model_element_id) in base_targets
            or item.model_element_id in base_targets
        ]
        refined_targets = sorted(
            {item.model_element_id for item in related_matches}
        )
        target_ids = refined_targets or sorted(base_targets)
        resolution = (
            "resolved"
            if refined_targets or sink_fact.resolution == "resolved"
            else "coarse" if base_targets else "unresolved"
        )
        constraint_ids = sorted(
            {
                value
                for item in related_matches
                for value in item.constraint_ids
            }
            | {
                value
                for target in target_ids
                for value in attachments.get(target, ((), ()))[0]
            }
        )
        dependency_ids = sorted(
            {
                value
                for item in related_matches
                for value in item.dependency_ids
            }
            | {
                value
                for target in target_ids
                for value in attachments.get(target, ((), ()))[1]
            }
        )
        flow_id = stable_model_id(
            "taintflow",
            endpoint_id,
            parameter_id,
            sink_id,
            slot_kind,
            str(argument_index if argument_index is not None else -1),
            ",".join(target_ids),
        )
        result[flow_id] = EndpointParameterTaintFlow(
            flow_id=flow_id,
            endpoint_node_id=endpoint_id,
            parameter_id=parameter_id,
            parameter_name=parameter.name,
            parameter_path=list(parameter.path),
            sink_id=sink_id,
            terminal_node_id=terminal_id,
            sink_slot_kind=slot_kind,
            sink_argument_index=argument_index,
            target_model_element_ids=target_ids,
            constraint_ids=constraint_ids,
            dependency_ids=dependency_ids,
            resolution=resolution,
            confidence=0.9 if resolution == "resolved" else 0.65,
            source=SourceLocation(
                file_path=_normalize_path(source_file), start_line=source_line
            ),
            sink=SourceLocation(
                file_path=_normalize_path(sink_file), start_line=sink_line
            ),
            reason=(
                "CodeQL global taint tracking found a may-flow from the endpoint "
                f"value to the persistence {slot_kind.replace('-', ' ')}"
                + (
                    f" {argument_index}" if argument_index is not None else ""
                )
                + ". "
                + (
                    "A deterministic reachable-name mapping resolves the terminal to "
                    "the listed persistent members."
                    if refined_targets
                    else (
                        "The ORM member-write sink directly resolves the listed member."
                        if sink_fact.resolution == "resolved"
                        else "The terminal is mapped only at persistent type/table granularity."
                    )
                )
            ),
        )
    return sorted(result.values(), key=lambda item: item.flow_id), warnings


def _element_parents(models: PersistenceModelBundle) -> dict[str, str]:
    result: dict[str, str] = {}
    for orm_type in models.orm.types:
        for element in [*orm_type.attributes, *orm_type.associations]:
            result[element.model_id] = orm_type.model_id
    for table in models.db_schema.tables:
        for column in table.columns:
            result[column.model_id] = table.model_id
    return result


def _element_attachments(
    models: PersistenceModelBundle,
) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    result: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for orm_type in models.orm.types:
        for element in [orm_type, *orm_type.attributes, *orm_type.associations]:
            result[element.model_id] = (
                tuple(element.constraint_ids), tuple(element.dependency_ids)
            )
    for table in models.db_schema.tables:
        for element in [table, *table.columns]:
            result[element.model_id] = (
                tuple(element.constraint_ids), tuple(element.dependency_ids)
            )
    return result


def _symbol_method_name(symbol: str) -> str | None:
    _, separator, declaration = symbol.partition("#")
    if not separator:
        return None
    name = declaration.split("(", 1)[0].strip()
    return name or None


def _normalize_path(value: str) -> str:
    return value.replace("\\", "/")


def _project_fingerprint(project: Path) -> str:
    """Hash Java/build inputs that can change a no-build CodeQL database."""

    digest = hashlib.sha256()
    ignored = {".git", ".gradle", ".idea", ".venv", "node_modules", "target", "build", "out"}
    candidates: list[Path] = []
    for path in project.rglob("*"):
        relative_parts = path.relative_to(project).parts
        if not path.is_file() or any(part in ignored for part in relative_parts):
            continue
        if path.suffix.lower() == ".java" or path.name in {
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradle.properties",
        }:
            candidates.append(path)
    for path in sorted(candidates):
        relative = path.relative_to(project).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            stat = path.stat()
            digest.update(f"{stat.st_size}:{stat.st_mtime_ns}".encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _ql_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _resolve_command(command: str) -> str | None:
    candidate = Path(command)
    if candidate.parent != Path(".") or candidate.is_absolute():
        return str(candidate.resolve()) if candidate.is_file() else None
    return shutil.which(command)


def _run_command(
    command: Sequence[str], cwd: Path | None, timeout: float
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        timeout=timeout,
        check=True,
        text=True,
        capture_output=True,
    )


_REACHABILITY_QUERY_TEMPLATE = r'''/*
 * Persispector-generated, project-scoped endpoint-to-persistence reachability.
 * Query contract: endpoint-persistence-reach-taint-v3.
 */

import java

private predicate generatedEndpointFact(
  string filePath, int methodLine, string endpointId,
  string ownerType, string methodName
) {
    __ENDPOINT_ROWS__
}

private predicate generatedTerminalFact(
  string terminalId, string matchKind, string ownerType,
  string methodName, string filePath, int line
) {
    __TERMINAL_ROWS__
}

private predicate endpointRoot(Callable endpoint, string endpointId) {
  exists(string filePath, int evidenceLine,
         string ownerType, string methodName |
    generatedEndpointFact(
      filePath, evidenceLine, endpointId, ownerType, methodName
    ) and
    endpoint.getLocation().getFile().getRelativePath() = filePath and
    (ownerType = "" or endpoint.getDeclaringType().getQualifiedName() = ownerType) and
    (methodName = "" or endpoint.getName() = methodName) and
    (
      endpoint.getLocation().getStartLine() = evidenceLine
      or
      exists(Annotation annotation |
        annotation = endpoint.getAnAnnotation() and
        annotation.getLocation().getStartLine() = evidenceLine
      )
    )
  )
}

private predicate receiverHasType(MethodCall call, string ownerType) {
  exists(RefType receiverType |
    receiverType = call.getQualifier().getType() and
    receiverType.getASupertype*().getQualifiedName() = ownerType
  )
}

private predicate terminalCall(
  Call call, string terminalId, string methodName
) {
  exists(string matchKind, string ownerType, string expectedMethod,
         string filePath, int line |
    generatedTerminalFact(
      terminalId, matchKind, ownerType, expectedMethod, filePath, line
    ) and
    methodName = call.getCallee().getName() and
    (
      matchKind = "location" and
      call.getLocation().getFile().getRelativePath() = filePath and
      call.getLocation().getStartLine() = line
      or
      matchKind = "method" and expectedMethod = methodName and
      (
        call.getCallee().getDeclaringType().getQualifiedName() = ownerType
        or
        exists(MethodCall methodCall |
          methodCall = call and receiverHasType(methodCall, ownerType)
        )
      )
      or
      matchKind = "type" and
      exists(MethodCall methodCall |
        methodCall = call and
        (
          methodCall.getMethod().getDeclaringType().getQualifiedName() = ownerType
          or receiverHasType(methodCall, ownerType)
        )
      )
    )
  )
}

from Callable endpoint, Call call, string endpointId,
     string terminalId, string methodName
where
  endpointRoot(endpoint, endpointId) and
  terminalCall(call, terminalId, methodName) and
  endpoint.polyCalls*(call.getCaller())
select
  endpointId, terminalId,
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(), call.getLocation().getStartColumn(),
  methodName, endpoint.getLocation().getStartLine()
'''


_QUERY_TEMPLATE = r'''/*
 * Persispector-generated, project-scoped endpoint-to-persistence taint relation.
 * Query contract: endpoint-persistence-taint-v1.
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

private predicate generatedSourceFact(
  string filePath, int methodLine, int parameterLine, int parameterIndex,
  string endpointId, string parameterId, string sourceKind,
  string propertyName, string accessorName
) {
    __SOURCE_ROWS__
}

private predicate generatedSinkFact(
  string filePath, int line, string methodName,
  string sinkId, string terminalId
) {
    __SINK_ROWS__
}

private predicate generatedOrmMemberSink(
  string ownerType, string setterName, string memberName,
  string sinkId, string terminalId
) {
    __ORM_SINK_ROWS__
}

private predicate rootParameterSource(
  DataFlow::Node root, string endpointId, string parameterId,
  string sourceKind, string propertyName, string accessorName
) {
    exists(Parameter parameter, int methodLine, int parameterLine |
      root = DataFlow::parameterNode(parameter) and
      generatedSourceFact(
        parameter.getCallable().getLocation().getFile().getRelativePath(),
        methodLine, parameterLine, parameter.getPosition(), endpointId,
        parameterId, sourceKind, propertyName, accessorName
      ) and
      (
        parameter.getCallable().getLocation().getStartLine() = methodLine
        or parameter.getLocation().getStartLine() = parameterLine
      )
    )
}

private class RootParameterSource extends DataFlow::Node {
  RootParameterSource() {
    exists(string endpointId, string parameterId, string sourceKind,
           string propertyName, string accessorName |
      rootParameterSource(
        this, endpointId, parameterId, sourceKind, propertyName, accessorName
      )
    )
  }
}

private predicate propertyAccess(
  string sourceKind, string accessorName, Expr qualifier, Expr value
) {
  sourceKind = "property" and
  (
    exists(MethodCall call |
      call.getMethod().getName() = accessorName and
      call.getNumArgument() = 0 and
      qualifier = call.getQualifier() and value = call
    )
    or
    exists(FieldAccess access |
      access.getField().getName() = accessorName and
      qualifier = access.getQualifier() and value = access
    )
  )
}

private predicate propertyPropagationStep(
  DataFlow::Node before, DataFlow::Node after
) {
  exists(MethodCall call |
    call.getNumArgument() = 0 and
    before.asExpr() = call.getQualifier() and after.asExpr() = call
  )
  or
  exists(FieldAccess access |
    before.asExpr() = access.getQualifier() and after.asExpr() = access
  )
}

private module RootConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RootParameterSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::Node root, string endpointId, string parameterId,
           string sourceKind, string propertyName, string accessorName,
           Expr qualifier, Expr value |
      rootParameterSource(
        root, endpointId, parameterId, sourceKind, propertyName, accessorName
      ) and
      propertyAccess(
        sourceKind, accessorName, qualifier, value
      ) and sink.asExpr() = qualifier
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node before, DataFlow::Node after) {
    propertyPropagationStep(before, after)
  }
}

private module RootFlow = TaintTracking::Global<RootConfig>;

private predicate endpointTaintSource(
  DataFlow::Node source, string endpointId, string parameterId
) {
    exists(DataFlow::Node root, string sourceKind, string propertyName,
           string accessorName |
      rootParameterSource(
        root, endpointId, parameterId, sourceKind, propertyName, accessorName
      ) and
      (
        sourceKind = "direct" and source = root
        or
        exists(Expr qualifier, Expr value |
          propertyAccess(sourceKind, accessorName, qualifier, value) and
          RootFlow::flow(root, DataFlow::exprNode(qualifier)) and
          source.asExpr() = value
        )
      )
    )
}

private class EndpointTaintSource extends DataFlow::Node {
  EndpointTaintSource() {
    exists(string endpointId, string parameterId |
      endpointTaintSource(this, endpointId, parameterId)
    )
  }
}

private predicate persistenceSink(
  DataFlow::ExprNode sink, string sinkId, string terminalId,
  string slotKind, int argumentIndex
) {
    exists(MethodCall call, string methodName, string ownerType, string memberName |
      (
        generatedSinkFact(
          call.getLocation().getFile().getRelativePath(),
          call.getLocation().getStartLine(), methodName, sinkId, terminalId
        ) and
        ownerType = "" and
        memberName = "" and
        slotKind = "argument" and
        call.getMethod().getName() = methodName and
        sink.asExpr() = call.getArgument(argumentIndex)
        or
        generatedOrmMemberSink(
          ownerType, methodName, memberName, sinkId, terminalId
        ) and
        call.getMethod().getName() = methodName and
        call.getMethod().getDeclaringType().getQualifiedName() = ownerType and
        slotKind = "argument" and argumentIndex = 0 and
        sink.asExpr() = call.getArgument(0)
      )
    )
    or
    exists(AssignExpr assignment, FieldAccess access, string ownerType,
           string setterName, string memberName |
      generatedOrmMemberSink(
        ownerType, setterName, memberName, sinkId, terminalId
      ) and
      assignment.getDest() = access and
      access.getField().getDeclaringType().getQualifiedName() = ownerType and
      access.getField().getName() = memberName and
      slotKind = "field-write" and argumentIndex = -1 and
      sink.asExpr() = assignment.getRhs()
    )
}

private class PersistenceSink extends DataFlow::ExprNode {
  PersistenceSink() {
    exists(string sinkId, string terminalId, string slotKind, int argumentIndex |
      persistenceSink(this, sinkId, terminalId, slotKind, argumentIndex)
    )
  }
}

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof EndpointTaintSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof PersistenceSink
  }

  predicate isAdditionalFlowStep(DataFlow::Node before, DataFlow::Node after) {
    propertyPropagationStep(before, after)
  }
}

private module Flow = TaintTracking::Global<Config>;

from EndpointTaintSource source, PersistenceSink sink,
     string endpointId, string parameterId, string sinkId, string terminalId,
     string slotKind, int argumentIndex
where
  Flow::flow(source, sink) and
  endpointTaintSource(source, endpointId, parameterId) and
  persistenceSink(sink, sinkId, terminalId, slotKind, argumentIndex)
select
  endpointId, parameterId, sinkId, terminalId, slotKind, argumentIndex,
  sink.getLocation().getFile().getRelativePath(),
  sink.getLocation().getStartLine(), sink.getLocation().getStartColumn(),
  source.getLocation().getFile().getRelativePath(),
  source.getLocation().getStartLine(), source.getLocation().getStartColumn()
'''
