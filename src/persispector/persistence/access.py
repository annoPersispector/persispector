"""Deterministically connect Java persistence access points to schema models.

This module builds the persistence-terminal portion of the graph. The endpoint
extension traverses CLDK calls until it reaches a ``java-type`` or
``java-callable`` symbol recorded here, then continues through ``accesses`` and
``maps-to`` edges to the ORM and DB-schema models.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree

import javalang
from sqlglot import exp

from persispector.annotations import JavaAnnotation, parse_annotation
from persispector.persistence.modeling import stable_model_id
from persispector.persistence.models import (
    AccessOperation,
    PersistenceAccessEdge,
    PersistenceAccessGraph,
    PersistenceAccessNode,
    PersistenceModelBundle,
    SourceLocation,
)
from persispector.persistence.sql_parsing import ast_errors, parse_sql


_IGNORED_DIRECTORIES = {
    ".git", ".gradle", ".idea", ".venv", "node_modules", "target", "build", "out"
}
_ORM_REPOSITORIES = {
    "Repository", "CrudRepository", "ListCrudRepository",
    "PagingAndSortingRepository", "ListPagingAndSortingRepository",
    "JpaRepository", "JpaSpecificationExecutor",
}
_MYBATIS_BASES = {"BaseMapper", "Mapper", "MySqlMapper"}
_MYBATIS_SQL_ANNOTATIONS = {
    "Select": "select", "Insert": "insert", "Update": "update", "Delete": "delete"
}
_JDBC_METHODS = {
    "query", "queryForList", "queryForMap", "queryForObject", "queryForRowSet",
    "update", "batchUpdate", "execute", "executeQuery", "executeUpdate",
    "prepareStatement", "prepareCall", "addBatch",
}
_JDBC_TYPES = {
    "JdbcTemplate", "NamedParameterJdbcTemplate", "JdbcClient", "Connection",
    "Statement", "PreparedStatement", "CallableStatement",
}
_DYNAMIC_SQL_IDENTIFIER = "__persispector_dynamic_identifier__"


class PersistenceAccessGraphBuilder:
    """Build access terminals from CLDK metadata plus structural XML/SQL parsing."""

    def __init__(
        self,
        analysis: Any,
        project_path: str | Path,
        models: PersistenceModelBundle,
        *,
        include_tests: bool = False,
        max_file_chars: int = 1_000_000,
    ) -> None:
        self.analysis = analysis
        self.project_path = Path(project_path).resolve()
        self.models = models
        self.include_tests = include_tests
        self.max_file_chars = max_file_chars
        self.graph = PersistenceAccessGraph()
        self._nodes: dict[str, PersistenceAccessNode] = {}
        self._edges: dict[str, PersistenceAccessEdge] = {}
        self._warnings: set[str] = set()
        self._classes: dict[str, Any] = analysis.get_classes()
        self._imports_by_file = self._collect_imports()
        self._mybatis_type_names = self._discover_mybatis_type_names()

    def build(self) -> PersistenceAccessGraph:
        self._seed_model_nodes_and_correlations()
        self._discover_java_access()
        self._discover_mybatis_xml()
        self.graph.nodes = sorted(self._nodes.values(), key=lambda item: item.node_id)
        self.graph.edges = sorted(self._edges.values(), key=lambda item: item.edge_id)
        self.graph.warnings = sorted(self._warnings)
        return self.graph

    def _seed_model_nodes_and_correlations(self) -> None:
        for orm_type in self.models.orm.types:
            self._model_node(
                orm_type.model_id, "orm-type", orm_type.qualified_name,
                symbol=orm_type.qualified_name, mechanism="orm", sources=orm_type.sources,
            )
        for table in self.models.db_schema.tables:
            context = next(
                (
                    item
                    for item in self.models.db_schema.contexts
                    if item.context_id == table.schema_context_id
                ),
                None,
            )
            context_label = context.label if context else table.schema_context_id or "default"
            self._model_node(
                table.model_id,
                "db-schema-table",
                f"{table.name.physical_name or '?'} [{context_label}]",
                mechanism=None,
                sources=table.sources,
                metadata={
                    "schema_context_id": table.schema_context_id or "",
                    "schema_context": context_label,
                    "table_name": table.name.physical_name or "?",
                },
            )
        orm_by_id = {item.model_id: item for item in self.models.orm.types}
        for correlation in self.models.correlations:
            if correlation.kind != "table":
                continue
            orm_type = orm_by_id.get(correlation.orm_element_id)
            if not orm_type:
                continue
            source = self._node_for_model(orm_type.model_id)
            if correlation.db_schema_element_id:
                target = self._node_for_model(correlation.db_schema_element_id)
            else:
                target = self._unresolved_table_node(
                    orm_type.table.physical_name or orm_type.table.logical_name or "?"
                )
            self._edge(
                "maps-to", source, target, "cross-layer", [], correlation.status,
                correlation.reason, orm_type.sources,
            )

    def _discover_java_access(self) -> None:
        explicit_type_tables = self._explicit_java_table_names()
        orm_by_name = self._orm_types_by_name()
        for qualified, java_type in self._classes.items():
            source = self._java_source(qualified)
            if source is None:
                continue
            display = self._display_path(source)
            if not self.include_tests and self._is_test_path(display):
                continue
            type_source = SourceLocation(
                file_path=display,
                start_line=self._find_type_line(source, qualified.rsplit(".", 1)[-1]),
            )
            bases = [*list(java_type.extends_list or []), *list(java_type.implements_list or [])]
            repository_domain = self._repository_domain(bases, source)
            mybatis_domain = self._generic_domain(
                bases, _MYBATIS_BASES | self._mybatis_type_names
            )
            is_mybatis = qualified in self._mybatis_type_names

            type_node: str | None = None
            if repository_domain:
                target_orm = self._resolve_orm_type(repository_domain, orm_by_name)
                type_node = self._java_type_node(qualified, "orm", [type_source])
                if target_orm:
                    self._edge(
                        "accesses", type_node, self._node_for_model(target_orm.model_id),
                        "orm", ["unknown"], "matched",
                        "Repository generic domain type explicitly resolves to an ORM type.",
                        [type_source],
                    )
                else:
                    self._warnings.add(
                        f"Could not resolve ORM repository domain {repository_domain!r} in {qualified}."
                    )
            if is_mybatis:
                type_node = type_node or self._java_type_node(qualified, "mybatis", [type_source])
                if mybatis_domain:
                    table_name = self._resolve_explicit_type_table(
                        mybatis_domain, explicit_type_tables
                    )
                    if table_name:
                        for target, resolution in self._table_targets(
                            table_name, [type_source]
                        ):
                            self._edge(
                                "accesses", type_node, target, "mybatis", ["unknown"], resolution,
                                "MyBatis mapper generic domain has an explicit table annotation.",
                                [type_source],
                            )

            field_types = {
                variable: field.type
                for field in java_type.field_declarations or []
                for variable in field.variables or []
            }
            for signature, callable_decl in (java_type.callable_declarations or {}).items():
                callable_source = SourceLocation(
                    file_path=display,
                    start_line=_positive(callable_decl.start_line),
                    end_line=_positive(callable_decl.end_line),
                )
                annotations = [
                    parse_annotation(item) for item in callable_decl.annotations or []
                ]
                sql_annotations = [
                    item for item in annotations if item.name in _MYBATIS_SQL_ANNOTATIONS
                ]
                native_queries = [
                    item for item in annotations
                    if item.name == "Query" and _annotation_true(item, "nativeQuery")
                ]
                needs_callable = bool(
                    sql_annotations or native_queries or repository_domain or is_mybatis
                )
                callable_node = (
                    self._java_callable_node(
                        qualified, signature, "mybatis" if is_mybatis else "orm",
                        [callable_source],
                    )
                    if needs_callable else None
                )
                if type_node and callable_node:
                    self._edge(
                        "declares", type_node, callable_node,
                        "mybatis" if is_mybatis else "orm", [], "not-applicable",
                        "Java type declares the persistence access callable.", [callable_source],
                    )
                if repository_domain and callable_node:
                    target_orm = self._resolve_orm_type(repository_domain, orm_by_name)
                    if target_orm:
                        self._edge(
                            "accesses", callable_node, self._node_for_model(target_orm.model_id),
                            "orm", [_repository_operation(signature)], "matched",
                            "Repository callable operates on its explicit generic ORM domain.",
                            [callable_source],
                        )
                for annotation in [*sql_annotations, *native_queries]:
                    operation = _MYBATIS_SQL_ANNOTATIONS.get(annotation.name, "unknown")
                    for query in annotation.values("value"):
                        self._connect_query(
                            callable_node, query,
                            "mybatis" if annotation.name in _MYBATIS_SQL_ANNOTATIONS else "orm",
                            operation, [callable_source],
                            f"SQL is explicitly declared by @{annotation.name}.",
                        )
                self._discover_callable_calls(
                    qualified, signature, callable_decl, field_types, callable_source
                )

    def _discover_callable_calls(
        self,
        qualified: str,
        signature: str,
        callable_decl: Any,
        field_types: dict[str, str],
        source: SourceLocation,
    ) -> None:
        variable_types = dict(field_types)
        variable_types.update(
            {item.name: item.type for item in callable_decl.parameters or []}
        )
        variable_types.update(
            {item.name: item.type for item in callable_decl.variable_declarations or []}
        )
        for call in callable_decl.call_sites or []:
            call_source = SourceLocation(
                file_path=source.file_path,
                start_line=_positive(call.start_line),
                end_line=_positive(call.end_line),
            )
            receiver_type = variable_types.get(call.receiver_expr or "", call.receiver_type or "")
            receiver_simple = _simple_type(receiver_type) or _constructed_type(
                call.receiver_expr or ""
            )
            is_jdbc = receiver_simple in _JDBC_TYPES
            is_native_jpa = (
                _simple_type(receiver_type) == "EntityManager"
                and call.method_name == "createNativeQuery"
            )
            if _simple_type(receiver_type) in {"EntityManager", "Session"}:
                target_orm = self._orm_target_from_call(
                    call, variable_types, self._orm_types_by_name()
                )
                if target_orm:
                    callable_node = self._java_callable_node(
                        qualified, signature, "orm", [source]
                    )
                    self._edge(
                        "accesses", callable_node,
                        self._node_for_model(target_orm.model_id), "orm",
                        [_orm_call_operation(call.method_name)], "matched",
                        f"{_simple_type(receiver_type)}.{call.method_name} explicitly references an ORM type.",
                        [call_source],
                    )
            if not is_jdbc and not is_native_jpa:
                continue
            query = None
            for argument in call.argument_expr or []:
                candidate = _java_sql_template(argument)
                if candidate is not None:
                    query = candidate
                    break
            if not query:
                if call.argument_expr:
                    self._warnings.add(
                        f"Non-constant SQL access left unresolved at {_location_text(call_source)} "
                        f"({receiver_simple}.{call.method_name})."
                    )
                continue
            mechanism = "orm" if is_native_jpa else "jdbc"
            callable_node = self._java_callable_node(
                qualified, signature, mechanism, [source]
            )
            self._connect_query(
                callable_node, query, mechanism, _call_operation(call.method_name), [call_source],
                f"Constant SQL is passed to {receiver_simple}.{call.method_name}.",
            )

    @staticmethod
    def _orm_target_from_call(
        call: Any, variable_types: dict[str, str], orm_by_name: dict[str, Any]
    ) -> Any | None:
        arguments = list(call.argument_expr or [])
        if not arguments:
            return None
        candidate: str | None = None
        if call.method_name in {"find", "getReference", "get", "load"}:
            first = arguments[0].strip()
            candidate = first[:-6] if first.endswith(".class") else None
        elif call.method_name in {"persist", "merge", "remove", "save", "update"}:
            candidate = variable_types.get(arguments[0].strip())
        return (
            PersistenceAccessGraphBuilder._resolve_orm_type(candidate, orm_by_name)
            if candidate else None
        )

    def _discover_mybatis_xml(self) -> None:
        for path in self._files(".xml"):
            display = self._display_path(path)
            try:
                if path.stat().st_size > self.max_file_chars:
                    continue
                text = path.read_text(encoding="utf-8")
                root = ElementTree.fromstring(text)
            except (OSError, UnicodeDecodeError, ElementTree.ParseError):
                continue
            if _local_name(root.tag) != "mapper" or not root.attrib.get("namespace"):
                continue
            namespace = root.attrib["namespace"].strip()
            fragments = {
                item.attrib["id"]: item
                for item in root
                if _local_name(item.tag) == "sql" and item.attrib.get("id")
            }
            type_source = SourceLocation(file_path=display, start_line=1)
            type_node = self._java_type_node(namespace, "mybatis", [type_source])
            for statement in root:
                tag = _local_name(statement.tag)
                statement_id = statement.attrib.get("id")
                if tag not in {"select", "insert", "update", "delete"} or not statement_id:
                    continue
                start_line = _xml_element_line(text, tag, statement_id)
                source = SourceLocation(file_path=display, start_line=start_line)
                matching_signatures = [
                    signature
                    for signature in (
                        getattr(self._classes.get(namespace), "callable_declarations", {}) or {}
                    )
                    if signature.split("(", 1)[0] == statement_id
                ]
                exact = len(matching_signatures) == 1
                callable_node = self._java_callable_node(
                    namespace,
                    matching_signatures[0] if exact else statement_id,
                    "mybatis",
                    [source],
                    exact_signature=exact,
                )
                self._edge(
                    "declares", type_node, callable_node, "mybatis", [], "not-applicable",
                    "MyBatis mapper namespace declares this statement ID.", [source],
                )
                query = _render_mybatis_xml(statement, fragments)
                self._connect_query(
                    callable_node, query, "mybatis", tag, [source],
                    "MyBatis XML statement contains an explicit table reference.",
                )

    def _connect_query(
        self,
        source_node: str | None,
        query: str,
        mechanism: str,
        operation: str,
        sources: list[SourceLocation],
        reason: str,
    ) -> None:
        if source_node is None:
            return
        parsed = _query_tables(query, sources[0].file_path)
        if parsed is None:
            self._warnings.add(
                f"Could not structurally resolve SQL access at {_location_text(sources[0])}."
            )
            return
        tables, parsed_operation = parsed
        operation_value = (
            parsed_operation if operation == "unknown" else operation
        )
        for table_name in tables:
            if _DYNAMIC_SQL_IDENTIFIER in table_name:
                self._warnings.add(
                    f"Dynamic SQL table reference left unresolved at {_location_text(sources[0])}."
                )
            for target, resolution in self._table_targets(table_name, sources):
                self._edge(
                    "accesses", source_node, target, mechanism,
                    [_valid_operation(operation_value)], resolution, reason, sources,
                )

    def _explicit_java_table_names(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for qualified, java_type in self._classes.items():
            for raw in java_type.annotations or []:
                annotation = parse_annotation(raw)
                if annotation.name not in {"Table", "TableName"}:
                    continue
                name = annotation.value("name", "value")
                if name:
                    result[qualified] = name
        return result

    def _collect_imports(self) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for unit in self.analysis.get_compilation_units():
            path = Path(unit.file_path)
            if not path.is_absolute():
                path = self.project_path / path
            result[str(path.resolve())] = set(unit.imports or [])
        return result

    def _discover_mybatis_type_names(self) -> set[str]:
        """Resolve custom mapper base interfaces by a small type-hierarchy closure."""

        result: set[str] = set()
        for qualified, java_type in self._classes.items():
            source = self._java_source(qualified)
            imports = self._imports_by_file.get(str(source.resolve()), set()) if source else set()
            raw_annotations = list(java_type.annotations or [])
            has_mybatis_annotation = any(
                raw.lstrip("@").startswith("org.apache.ibatis.annotations.Mapper")
                for raw in raw_annotations
            ) or (
                any(parse_annotation(raw).name == "Mapper" for raw in raw_annotations)
                and any(
                    imported == "org.apache.ibatis.annotations.Mapper"
                    or imported == "org.apache.ibatis.annotations.*"
                    for imported in imports
                )
            )
            bases = [*list(java_type.extends_list or []), *list(java_type.implements_list or [])]
            has_known_base = any(
                _base_name(base) in _MYBATIS_BASES
                and (
                    any(marker in base for marker in ("mybatis", "baomidou"))
                    or any(
                        marker in imported
                        for imported in imports
                        for marker in ("mybatis", "baomidou")
                    )
                )
                for base in bases
            )
            if has_mybatis_annotation or has_known_base:
                result.add(qualified)

        changed = True
        while changed:
            changed = False
            known_simple = {item.rsplit(".", 1)[-1] for item in result}
            for qualified, java_type in self._classes.items():
                if qualified in result:
                    continue
                bases = [
                    *list(java_type.extends_list or []),
                    *list(java_type.implements_list or []),
                ]
                if any(
                    _erase_type(base) in result or _base_name(base) in known_simple
                    for base in bases
                ):
                    result.add(qualified)
                    changed = True
        # Generic-domain lookup accepts both qualified and simple custom bases.
        return result | {item.rsplit(".", 1)[-1] for item in result}

    def _orm_types_by_name(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for item in self.models.orm.types:
            result[item.qualified_name] = item
            result.setdefault(item.qualified_name.rsplit(".", 1)[-1], item)
        return result

    @staticmethod
    def _resolve_orm_type(name: str, by_name: dict[str, Any]) -> Any | None:
        cleaned = _erase_type(name)
        return by_name.get(cleaned) or by_name.get(cleaned.rsplit(".", 1)[-1])

    def _resolve_explicit_type_table(
        self, name: str, mappings: dict[str, str]
    ) -> str | None:
        cleaned = _erase_type(name)
        if cleaned in mappings:
            return mappings[cleaned]
        matches = [
            table for qualified, table in mappings.items()
            if qualified.rsplit(".", 1)[-1] == cleaned.rsplit(".", 1)[-1]
        ]
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _generic_domain(bases: list[str], accepted: set[str]) -> str | None:
        for base in bases:
            raw_name = base.split("<", 1)[0].strip().rsplit(".", 1)[-1]
            if raw_name not in accepted or "<" not in base:
                continue
            arguments = _generic_arguments(base)
            if arguments:
                return arguments[0]
        return None

    def _repository_domain(self, bases: list[str], source: Path) -> str | None:
        imports = self._imports_by_file.get(str(source.resolve()), set())
        has_spring_data_import = any(
            imported.startswith("org.springframework.data.") for imported in imports
        )
        accepted_bases = [
            base for base in bases
            if _base_name(base) in _ORM_REPOSITORIES
            and (
                _base_name(base) != "Repository"
                or "org.springframework.data." in base
                or has_spring_data_import
            )
        ]
        return self._generic_domain(accepted_bases, _ORM_REPOSITORIES)

    def _table_targets(
        self, name: str, sources: list[SourceLocation]
    ) -> list[tuple[str, str]]:
        normalized = _normalize_table(name)
        if _DYNAMIC_SQL_IDENTIFIER in normalized:
            static_name = normalized.replace(_DYNAMIC_SQL_IDENTIFIER, "").strip(".")
            candidates = [
                item for item in self.models.db_schema.tables
                if static_name
                and _normalize_table(item.name.physical_name or "").rsplit(".", 1)[-1]
                == static_name.rsplit(".", 1)[-1]
            ]
            candidates = self._prefer_source_contexts(candidates, sources)
            if candidates:
                # Preserve every variant candidate for traversal, but do not
                # claim the runtime prefix/suffix resolves to a physical name.
                return [
                    (self._node_for_model(item.model_id), "unresolved")
                    for item in candidates
                ]
            return [(self._unresolved_table_node(name), "unresolved")]
        exact = [
            item for item in self.models.db_schema.tables
            if _normalize_table(item.name.physical_name or "") == normalized
        ]
        if len(exact) != 1 and "." in normalized:
            simple = normalized.rsplit(".", 1)[-1]
            exact = [
                item for item in self.models.db_schema.tables
                if _normalize_table(item.name.physical_name or "").rsplit(".", 1)[-1] == simple
            ]
        exact = self._prefer_source_contexts(exact, sources)
        if exact:
            return [
                (self._node_for_model(item.model_id), "matched") for item in exact
            ]
        return [(self._unresolved_table_node(name), "unresolved")]

    def _prefer_source_contexts(
        self, tables: list[Any], sources: list[SourceLocation]
    ) -> list[Any]:
        """Prefer the caller's build module but retain all database variants."""

        if not tables or not sources:
            return tables
        source_path = sources[0].file_path.replace("\\", "/").strip("/")
        contexts = {
            item.context_id: item for item in self.models.db_schema.contexts
        }
        module_matches: list[tuple[int, Any]] = []
        for table in tables:
            context = contexts.get(table.schema_context_id)
            if context is None:
                continue
            matches = (
                context.module == "."
                or source_path == context.module
                or source_path.startswith(context.module.rstrip("/") + "/")
            )
            if matches:
                specificity = 0 if context.module == "." else len(
                    context.module.split("/")
                )
                module_matches.append((specificity, table))
        if not module_matches:
            return tables
        most_specific = max(item[0] for item in module_matches)
        return [
            table for specificity, table in module_matches
            if specificity == most_specific
        ]

    def _model_node(
        self, model_id: str, kind: str, label: str, *, symbol: str | None = None,
        mechanism: str | None = None, sources: list[SourceLocation] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> str:
        node_id = stable_model_id("accn", "model", model_id)
        self._nodes[node_id] = PersistenceAccessNode(
            node_id=node_id, kind=kind, label=label, symbol=symbol,
            model_element_id=model_id, mechanism=mechanism, sources=sources or [],
            metadata=metadata or {},
        )
        return node_id

    def _node_for_model(self, model_id: str) -> str:
        node_id = stable_model_id("accn", "model", model_id)
        if node_id not in self._nodes:
            raise KeyError(f"No access-graph node for model element {model_id}")
        return node_id

    def _java_type_node(
        self, qualified: str, mechanism: str, sources: list[SourceLocation]
    ) -> str:
        node_id = stable_model_id("accn", "java-type", qualified, mechanism)
        self._nodes.setdefault(
            node_id,
            PersistenceAccessNode(
                node_id=node_id, kind="java-type", label=qualified, symbol=qualified,
                mechanism=mechanism, sources=sources,
            ),
        )
        return node_id

    def _java_callable_node(
        self, qualified: str, signature: str, mechanism: str,
        sources: list[SourceLocation], *, exact_signature: bool = True,
    ) -> str:
        symbol = f"{qualified}#{signature}"
        node_id = stable_model_id("accn", "java-callable", symbol, mechanism)
        self._nodes.setdefault(
            node_id,
            PersistenceAccessNode(
                node_id=node_id, kind="java-callable", label=symbol, symbol=symbol,
                mechanism=mechanism, sources=sources,
                metadata={"symbol_match": "exact" if exact_signature else "type-and-method"},
            ),
        )
        return node_id

    def _unresolved_table_node(self, name: str) -> str:
        normalized = _normalize_table(name)
        node_id = stable_model_id("accn", "unresolved-table", normalized)
        self._nodes.setdefault(
            node_id,
            PersistenceAccessNode(
                node_id=node_id, kind="unresolved-table", label=name,
                metadata={"normalized_name": normalized},
            ),
        )
        return node_id

    def _edge(
        self, kind: str, source_id: str, target_id: str, mechanism: str,
        operations: list[str], resolution: str, reason: str,
        sources: list[SourceLocation],
    ) -> None:
        normalized_operations = sorted({_valid_operation(item) for item in operations})
        edge_id = stable_model_id(
            "acce", kind, source_id, target_id, mechanism, ",".join(normalized_operations)
        )
        self._edges.setdefault(
            edge_id,
            PersistenceAccessEdge(
                edge_id=edge_id, kind=kind, source_id=source_id, target_id=target_id,
                mechanism=mechanism, operations=normalized_operations,
                resolution=resolution, reason=reason, sources=sources,
            ),
        )

    def _java_source(self, qualified: str) -> Path | None:
        try:
            raw = self.analysis.get_java_file(qualified)
        except Exception:
            return None
        if not raw:
            return None
        path = Path(str(raw))
        return path if path.is_absolute() else self.project_path / path

    def _files(self, suffix: str) -> Iterable[Path]:
        for root, directories, files in os.walk(self.project_path):
            directories[:] = [item for item in directories if item not in _IGNORED_DIRECTORIES]
            root_path = Path(root)
            if not self.include_tests and self._is_test_path(self._display_path(root_path)):
                directories[:] = []
                continue
            for name in files:
                if name.lower().endswith(suffix):
                    yield root_path / name

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.project_path))
        except ValueError:
            return str(path.resolve())

    @staticmethod
    def _is_test_path(path: str) -> bool:
        normalized = "/" + path.replace("\\", "/").strip("/") + "/"
        return "/src/test/" in normalized or "/src/it/" in normalized

    @staticmethod
    def _find_type_line(path: Path, simple_name: str) -> int | None:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        match = re.search(
            rf"\b(?:class|interface|record|enum)\s+{re.escape(simple_name)}\b", text
        )
        return text.count("\n", 0, match.start()) + 1 if match else None


def build_persistence_access_graph(
    analysis: Any,
    project_path: str | Path,
    models: PersistenceModelBundle,
    *,
    include_tests: bool = False,
    max_file_chars: int = 1_000_000,
) -> PersistenceAccessGraph:
    return PersistenceAccessGraphBuilder(
        analysis, project_path, models,
        include_tests=include_tests, max_file_chars=max_file_chars,
    ).build()


def _query_tables(
    query: str, source_path: str
) -> tuple[list[str], AccessOperation] | None:
    sanitized = re.sub(r"#\{[^{}]*}", "NULL", query)
    sanitized = re.sub(r"\$\{[^{}]*}", _DYNAMIC_SQL_IDENTIFIER, sanitized)
    parsed = parse_sql(sanitized, source_path=source_path)
    if parsed.mode in {"failed", "opaque", "tolerant"} or not parsed.statements:
        return None
    tables: list[str] = []
    operations: list[str] = []
    for statement in parsed.statements:
        if ast_errors(statement) or isinstance(statement, exp.Command):
            return None
        ctes = {
            cte.alias_or_name.lower()
            for cte in statement.find_all(exp.CTE)
            if cte.alias_or_name
        }
        for table in statement.find_all(exp.Table):
            name = ".".join(part.name for part in table.parts if part.name)
            if name and name.lower() not in ctes and name not in tables:
                tables.append(name)
        operations.append(_statement_operation(statement))
    operation = operations[0] if len(set(operations)) == 1 else "unknown"
    return tables, _valid_operation(operation)


def _statement_operation(statement: exp.Expression) -> str:
    if isinstance(statement, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
        return "select"
    if isinstance(statement, exp.Insert):
        return "insert"
    if isinstance(statement, exp.Update):
        return "update"
    if isinstance(statement, exp.Delete):
        return "delete"
    if isinstance(statement, exp.Merge):
        return "merge"
    if isinstance(statement, (exp.Create, exp.Alter, exp.Drop)):
        return "ddl"
    return "unknown"


def _render_mybatis_xml(
    element: ElementTree.Element, fragments: dict[str, ElementTree.Element]
) -> str:
    parts: list[str] = [element.text or ""]
    for child in element:
        child_tag = _local_name(child.tag)
        if child_tag == "selectKey":
            # selectKey is a separate statement nested inside an insert.  It
            # must not be concatenated into the parent SQL AST.
            pass
        elif child_tag == "include":
            reference = child.attrib.get("refid", "").rsplit(".", 1)[-1]
            fragment = fragments.get(reference)
            if fragment is not None:
                parts.append(_render_mybatis_xml(fragment, fragments))
        else:
            parts.append(_render_mybatis_xml(child, fragments))
        parts.append(child.tail or "")
    return " ".join(parts)


def _java_sql_template(expression: str) -> str | None:
    """Evaluate literal concatenation and retain dynamic pieces as placeholders."""

    try:
        node = javalang.parse.parse_expression(expression)
    except (javalang.parser.JavaSyntaxError, TypeError):
        return None

    def evaluate(value: Any) -> str | None:
        if isinstance(value, javalang.tree.Literal) and value.value.startswith('"'):
            try:
                return json.loads(value.value)
            except (json.JSONDecodeError, TypeError):
                return None
        if isinstance(value, javalang.tree.BinaryOperation) and value.operator == "+":
            left, right = evaluate(value.operandl), evaluate(value.operandr)
            return left + right if left is not None and right is not None else None
        if isinstance(
            value,
            (
                javalang.tree.MemberReference,
                javalang.tree.MethodInvocation,
                javalang.tree.Cast,
            ),
        ):
            return _DYNAMIC_SQL_IDENTIFIER
        return None

    result = evaluate(node)
    # A bare variable is not evidence that the argument contains SQL.
    return result if result and result != _DYNAMIC_SQL_IDENTIFIER else None


def _generic_arguments(value: str) -> list[str]:
    start, end = value.find("<"), value.rfind(">")
    if start < 0 or end <= start:
        return []
    result: list[str] = []
    depth = 0
    mark = start + 1
    for index, char in enumerate(value[start + 1 : end], start=start + 1):
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(value[mark:index].strip())
            mark = index + 1
    result.append(value[mark:end].strip())
    return [item for item in result if item]


def _erase_type(value: str) -> str:
    return value.split("<", 1)[0].replace("? extends ", "").strip()


def _base_name(value: str) -> str:
    return _erase_type(value).rsplit(".", 1)[-1]


def _simple_type(value: str | None) -> str:
    return _erase_type(value or "").rsplit(".", 1)[-1]


def _constructed_type(expression: str) -> str:
    match = re.match(r"\s*new\s+([\w.$]+)", expression)
    return match.group(1).rsplit(".", 1)[-1] if match else ""


def _normalize_table(value: str) -> str:
    return value.strip().strip("`\"").lower()


def _annotation_true(annotation: JavaAnnotation, name: str) -> bool:
    return (annotation.value(name) or "").lower() == "true"


def _repository_operation(signature: str) -> AccessOperation:
    name = signature.split("(", 1)[0].lower()
    if name.startswith(("delete", "remove")):
        return "delete"
    if name.startswith(("save", "persist")):
        return "merge"
    return "select"


def _call_operation(name: str) -> AccessOperation:
    lowered = name.lower()
    if "query" in lowered:
        return "select"
    if "update" in lowered or lowered == "addbatch":
        return "unknown"
    if lowered == "preparecall":
        return "call"
    return "unknown"


def _orm_call_operation(name: str) -> AccessOperation:
    if name in {"find", "getReference", "get", "load"}:
        return "select"
    if name in {"persist", "save"}:
        return "insert"
    if name in {"remove", "delete"}:
        return "delete"
    if name in {"merge", "update"}:
        return "merge"
    return "unknown"


def _valid_operation(value: str) -> AccessOperation:
    allowed = {"select", "insert", "update", "delete", "merge", "call", "ddl"}
    return value if value in allowed else "unknown"  # type: ignore[return-value]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_element_line(text: str, tag: str, statement_id: str) -> int | None:
    # This search is provenance-only; XML structure, not this expression,
    # decides whether the element is a mapper statement.
    match = re.search(
        rf"<{re.escape(tag)}\b[^>]*\bid\s*=\s*(['\"]){re.escape(statement_id)}\1",
        text,
    )
    return text.count("\n", 0, match.start()) + 1 if match else None


def _positive(value: int | None) -> int | None:
    return value if value is not None and value > 0 else None


def _location_text(source: SourceLocation) -> str:
    return f"{source.file_path}:{source.start_line or '?'}"
