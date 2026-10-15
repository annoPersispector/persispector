"""Deterministic discovery of declared persistence evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
from io import StringIO
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree
from xml.sax import ContentHandler, SAXException, make_parser
from xml.sax.handler import feature_namespaces

from cldk import CLDK
from cldk.analysis import AnalysisLevel
from cldk.analysis.java import JavaAnalysis
import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.tokens import TokenType, Tokenizer
import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from persispector.annotations import parse_annotation
from persispector.persistence.access import build_persistence_access_graph
from persispector.persistence.endpoint_access import (
    extend_access_graph_with_endpoints,
    refresh_endpoint_parameter_matches,
)
from persispector.persistence.models import (
    EvidenceArtifact,
    ExtractedConstraint,
    PreparedPersistenceEvidence,
    SkippedInput,
    SourceLocation,
    OrmType,
)
from persispector.persistence.modeling import (
    assemble_persistence_models,
    build_orm_type,
    project_constraints,
)
from persispector.persistence.static_extraction import (
    StaticExtraction,
    extract_java_constraints,
    extract_liquibase_constraints,
    extract_sql_constraints,
)


# Bean Validation is persistence evidence only when it belongs to one of these
# mapped types. This gate prevents validation-only DTOs from entering a report.
MAPPED_TYPES = {"Entity", "MappedSuperclass", "Embeddable"}
PERSISTENCE_ANNOTATIONS = {
    "Entity", "MappedSuperclass", "Embeddable", "Embedded", "EmbeddedId",
    "Id", "IdClass", "Table", "SecondaryTable", "Column", "JoinColumn",
    "JoinColumns", "JoinTable", "ManyToOne", "OneToOne", "OneToMany",
    "ManyToMany", "ElementCollection", "CollectionTable", "MapKeyColumn",
    "AssociationOverride", "AssociationOverrides", "AttributeOverride",
    "AttributeOverrides", "ForeignKey", "CheckConstraint", "OrderColumn", "Basic",
    "Transient", "Inheritance", "DiscriminatorColumn", "DiscriminatorValue",
}
HIBERNATE_ANNOTATIONS = {
    "Check", "Checks", "OnDelete", "NaturalId",
}
VALIDATION_ANNOTATIONS = {
    "AssertFalse", "AssertTrue", "DecimalMax", "DecimalMin", "Digits",
    "Email", "Future", "FutureOrPresent", "Max", "Min", "Negative",
    "NegativeOrZero", "NotBlank", "NotEmpty", "NotNull", "Null", "Past",
    "PastOrPresent", "Pattern", "Positive", "PositiveOrZero", "Size", "Valid",
}
# Used only when generic SQLGlot parsing fails. It keeps malformed or
# dialect-specific constraint declarations available to the LLM without using
# text matching to classify SQL that has a usable AST.
DDL_FALLBACK_PATTERN = re.compile(
    r"\b(?:CREATE\s+TABLE|ALTER\s+TABLE|PRIMARY\s+KEY|FOREIGN\s+KEY|"
    r"CREATE\s+UNIQUE\s+INDEX|UNIQUE\s*\(|CHECK\s*\(|ADD\s+CONSTRAINT|"
    r"EXCLUDE\s+(?:USING\s+\w+\s*)?\()\b",
    re.IGNORECASE,
)
IGNORED_DIRECTORIES = {
    ".git", ".gradle", ".idea", ".venv", "node_modules", "target", "build", "out",
}


class _ChangeSetLineHandler(ContentHandler):
    """Collect XML change-set line ranges through SAX parser events."""

    def __init__(self) -> None:
        super().__init__()
        self.locator: Any = None
        self.starts: list[int] = []
        self.ranges: list[tuple[int, int]] = []

    def setDocumentLocator(self, locator: Any) -> None:  # noqa: N802
        self.locator = locator

    def startElementNS(  # noqa: N802
        self, name: tuple[str | None, str], qname: str | None, attrs: Any
    ) -> None:
        if name[1] == "changeSet":
            self.starts.append(self.locator.getLineNumber())

    def endElementNS(  # noqa: N802
        self, name: tuple[str | None, str], qname: str | None
    ) -> None:
        if name[1] == "changeSet" and self.starts:
            self.ranges.append((self.starts.pop(), self.locator.getLineNumber()))


class PersistenceEvidencePreparer:
    """Collect bounded Java and DB schema declarations without calling an LLM."""

    def __init__(
        self,
        analysis: JavaAnalysis,
        project_path: str | Path,
        *,
        max_artifact_chars: int = 48_000,
        max_file_chars: int = 1_000_000,
        include_tests: bool = False,
        endpoint_max_depth: int = 8,
        endpoint_max_methods: int = 1_000,
    ):
        self.analysis = analysis
        self.project_path = Path(project_path).resolve()
        self.max_artifact_chars = max(1, max_artifact_chars)
        self.max_file_chars = max(1, max_file_chars)
        self.include_tests = include_tests
        self.endpoint_max_depth = max(0, endpoint_max_depth)
        self.endpoint_max_methods = max(1, endpoint_max_methods)
        self._warnings: list[str] = []
        self._skipped: list[SkippedInput] = []
        self._deterministic_constraints: list[ExtractedConstraint] = []
        self._orm_types: list[OrmType] = []

    @classmethod
    def from_project(
        cls,
        project_path: str | Path,
        *,
        analysis_json_path: str | Path | None = None,
        eager: bool = False,
        **options: Any,
    ) -> "PersistenceEvidencePreparer":
        project = Path(project_path).resolve()
        # The symbol table provides resolved types, members, annotations, and
        # source locations without requiring the more expensive call graph.
        analysis = CLDK(language="java").analysis(
            project_path=project,
            analysis_level=AnalysisLevel.symbol_table,
            analysis_json_path=analysis_json_path,
            eager=eager,
        )
        return cls(analysis, project, **options)

    def prepare(self) -> PreparedPersistenceEvidence:
        self._warnings = []
        self._skipped = []
        self._deterministic_constraints = []
        self._orm_types = []
        artifacts = [*self._java_artifacts(), *self._db_schema_artifacts()]
        # Do not depend on filesystem traversal or analyzer iteration order.
        artifacts.sort(
            key=lambda item: (
                item.source.file_path,
                item.source.start_line or 0,
                item.artifact_id,
            )
        )
        artifact_order = {
            artifact.artifact_id: index for index, artifact in enumerate(artifacts)
        }
        self._deterministic_constraints.sort(
            key=lambda item: (
                artifact_order.get(item.evidence_ids[0], len(artifacts)),
                item.layer,
                item.kind,
                item.model_dump_json(),
            )
        )
        models = assemble_persistence_models(
            artifacts,
            self._deterministic_constraints,
            self._orm_types,
            max_context_chars=self.max_artifact_chars,
        )
        models.access_graph = build_persistence_access_graph(
            self.analysis,
            self.project_path,
            models,
            include_tests=self.include_tests,
            max_file_chars=self.max_file_chars,
        )
        models.access_graph = extend_access_graph_with_endpoints(
            self.analysis,
            self.project_path,
            models.access_graph,
            max_depth=self.endpoint_max_depth,
            max_methods_per_endpoint=self.endpoint_max_methods,
            include_tests=self.include_tests,
        )
        models = refresh_endpoint_parameter_matches(models)
        self._deterministic_constraints = project_constraints(models)
        self._deterministic_constraints.sort(
            key=lambda item: (
                artifact_order.get(item.evidence_ids[0], len(artifacts)),
                item.layer,
                item.kind,
                item.model_dump_json(),
            )
        )
        return PreparedPersistenceEvidence(
            project_path=str(self.project_path),
            artifacts=artifacts,
            deterministic_constraints=self._deterministic_constraints,
            models=models,
            skipped_inputs=self._skipped,
            warnings=self._warnings,
        )

    def _java_artifacts(self) -> list[EvidenceArtifact]:
        classes = self.analysis.get_classes()
        # Prefer CLDK's annotation declarations, then supplement them with a
        # source scan because some CLDK models omit meta-annotation metadata.
        custom_constraints = {
            qualified.rsplit(".", 1)[-1]
            for qualified, java_type in classes.items()
            if java_type.is_annotation_declaration
            # catch @javax.validation.Constraint and @jakarta.validation.Constraint
            # TODO: try to resolve the full qualified name of the annotation to avoid false positives
            and "Constraint" in self._annotation_names(java_type.annotations)
        }
        custom_constraints.update(self._custom_constraint_names())
        imports_by_file = self._imports_by_file()
        result: list[EvidenceArtifact] = []
        for qualified, java_type in classes.items():
            # Create one bounded artifact per mapped type. In particular, do
            # not collect validation annotations from arbitrary Java classes.
            if not (self._annotation_names(java_type.annotations) & MAPPED_TYPES):
                continue
            source_path = self._java_file(qualified)
            display_path = self._display_path(source_path)
            if not self.include_tests and self._is_test_path(display_path):
                continue
            imports = imports_by_file.get(str(source_path.resolve()), []) if source_path else []
            type_line = self._find_type_line(source_path, qualified.rsplit(".", 1)[-1])
            content, member_lines = self._mapped_type_content(
                qualified, java_type, imports, custom_constraints
            )
            lines = [line for line in [type_line, *member_lines] if line is not None]
            start_line = min(lines) if lines else None
            end_line = max(lines) if lines else start_line
            content, truncated = self._bound(content, display_path)
            artifact = self._artifact(
                "java-mapped-type",
                display_path,
                start_line,
                end_line,
                content,
                mapped_type=qualified,
                imports=imports,
                truncated=truncated,
                metadata={"declaration_kind": self._mapped_kind(java_type)},
            )
            self._orm_types.append(build_orm_type(artifact, java_type))
            self._record_static_extraction(
                artifact,
                extract_java_constraints(artifact, java_type, custom_constraints),
            )
            result.append(artifact)
        return result

    def _mapped_type_content(
        self,
        qualified: str,
        java_type: Any,
        imports: list[str],
        custom_constraints: set[str],
    ) -> tuple[str, list[int]]:
        # Member declarations are retained even when they have no relevant
        # annotations: their names and types give annotations their local
        # subject, but do not by themselves constitute constraints.
        relevant = PERSISTENCE_ANNOTATIONS | HIBERNATE_ANNOTATIONS | VALIDATION_ANNOTATIONS | custom_constraints
        lines = [
            f"mapped_type: {qualified}",
            "imports:",
            *(f"  {item}" for item in imports if self._relevant_import(item)),
            "type_annotations:",
            *(f"  {item}" for item in java_type.annotations or []),
            "fields:",
        ]
        source_lines: list[int] = []
        for field in java_type.field_declarations or []:
            annotations = [
                item for item in field.annotations or []
                if parse_annotation(item).name in relevant
            ]
            lines.append(
                f"  lines {field.start_line}-{field.end_line}: {field.type} "
                f"{', '.join(field.variables)}"
            )
            lines.extend(f"    {item}" for item in annotations)
            source_lines.extend([field.start_line, field.end_line])

        if java_type.record_components:
            lines.append("record_components:")
            for component in java_type.record_components:
                annotations = [
                    item for item in component.annotations or []
                    if parse_annotation(item).name in relevant
                ]
                lines.append(f"  {component.type} {component.name}")
                lines.extend(f"    {item}" for item in annotations)

        # JPA supports property access, so annotated getters must be evidence
        # alongside fields. Constructors are never persistent properties.
        property_methods = []
        for java_callable in (java_type.callable_declarations or {}).values():
            annotations = [
                item for item in java_callable.annotations or []
                if parse_annotation(item).name in relevant
            ]
            if annotations and not java_callable.is_constructor:
                property_methods.append((java_callable, annotations))
        if property_methods:
            lines.append("annotated_properties_or_methods:")
            for java_callable, annotations in property_methods:
                lines.append(
                    f"  lines {java_callable.start_line}-{java_callable.end_line}: "
                    f"{java_callable.declaration}"
                )
                lines.extend(f"    {item}" for item in annotations)
                source_lines.extend([java_callable.start_line, java_callable.end_line])
        return "\n".join(lines), source_lines

    def _db_schema_artifacts(self) -> list[EvidenceArtifact]:
        result: list[EvidenceArtifact] = []
        for path in self._candidate_files():
            display_path = self._display_path(path)
            try:
                size = path.stat().st_size
            except OSError as error:
                self._skipped.append(SkippedInput(file_path=display_path, reason=str(error)))
                continue
            if size > self.max_file_chars:
                self._skipped.append(
                    SkippedInput(
                        file_path=display_path,
                        reason=f"file exceeds max_file_chars={self.max_file_chars}",
                    )
                )
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                self._skipped.append(SkippedInput(file_path=display_path, reason=str(error)))
                continue
            if path.suffix.lower() == ".sql":
                # Flyway and schema.sql need no filename-specific treatment;
                # any SQL file containing constraint-bearing DDL is eligible.
                result.extend(
                    self._sql_artifacts(
                        display_path, text, self._db_schema_context(path)
                    )
                )
            elif self._looks_like_liquibase(path.suffix.lower(), text):
                # XML/YAML/JSON are classified by changelog structure rather
                # than extension alone, avoiding unrelated configuration files.
                result.extend(
                    self._liquibase_artifacts(
                        display_path,
                        path.suffix.lower(),
                        text,
                        self._db_schema_context(path),
                    )
                )
        return result

    def _sql_artifacts(
        self, file_path: str, text: str, context: dict[str, str]
    ) -> list[EvidenceArtifact]:
        result: list[EvidenceArtifact] = []
        for statement, start, end in self._split_sql(text):
            if not self._is_constraint_ddl(statement):
                continue
            content, truncated = self._bound(statement.strip(), file_path)
            artifact = self._artifact(
                "sql-ddl", file_path, start, end, content,
                truncated=truncated,
                metadata=dict(context),
            )
            self._record_static_extraction(artifact, extract_sql_constraints(artifact))
            result.append(artifact)
        return result

    def _liquibase_artifacts(
        self,
        file_path: str,
        suffix: str,
        text: str,
        context: dict[str, str],
    ) -> list[EvidenceArtifact]:
        # A change set is the natural provenance and retry boundary: changes in
        # one set should not invalidate or obscure extraction from another.
        chunks: list[tuple[str, int | None, int | None]] = []
        if suffix == ".xml":
            try:
                root = ElementTree.fromstring(text)
            except ElementTree.ParseError as error:
                self._skipped.append(
                    SkippedInput(file_path=file_path, reason=f"invalid Liquibase XML: {error}")
                )
                return []
            elements = [
                element for element in root.iter()
                if self._local_name(element.tag) == "changeSet"
            ]
            line_ranges = self._xml_changeset_lines(text)
            for index, element in enumerate(elements):
                start, end = line_ranges[index] if index < len(line_ranges) else (None, None)
                chunks.append(
                    (ElementTree.tostring(element, encoding="unicode"), start, end)
                )
        elif suffix in {".yaml", ".yml"}:
            try:
                document = yaml.compose(text)
            except yaml.YAMLError as error:
                self._skipped.append(
                    SkippedInput(file_path=file_path, reason=f"invalid Liquibase YAML: {error}")
                )
                return []
            for node in self._yaml_changeset_nodes(document):
                content = text[node.start_mark.index:node.end_mark.index].rstrip()
                chunks.append(
                    (
                        content,
                        node.start_mark.line + 1,
                        max(node.start_mark.line + 1, node.end_mark.line),
                    )
                )
        elif suffix == ".json":
            try:
                data = json.loads(text)
                for item in self._json_changesets(data):
                    chunks.append((json.dumps(item, indent=2, sort_keys=True), None, None))
            except (json.JSONDecodeError, TypeError) as error:
                self._skipped.append(SkippedInput(file_path=file_path, reason=f"invalid Liquibase JSON: {error}"))
                return []
        if not chunks:
            # Retain a structurally recognized changelog even when it contains
            # no individually addressable change set.
            chunks.append((text, 1, text.count("\n") + 1))

        result: list[EvidenceArtifact] = []
        for index, (content, start, end) in enumerate(chunks, start=1):
            bounded, truncated = self._bound(content.strip(), file_path)
            artifact_context = dict(context)
            dbms = self._liquibase_dbms(content, suffix)
            if dbms:
                self._set_db_schema_context(
                    artifact_context,
                    artifact_context.get("db_schema_module", "."),
                    dbms,
                )
            artifact = self._artifact(
                "liquibase-changeset", file_path, start, end, bounded,
                truncated=truncated,
                metadata={**artifact_context, "changeset_index": str(index)},
            )
            self._record_static_extraction(
                artifact, extract_liquibase_constraints(artifact)
            )
            result.append(artifact)
        return result

    def _record_static_extraction(
        self,
        artifact: EvidenceArtifact,
        extraction: StaticExtraction,
    ) -> None:
        """Attach static results and preserve only unresolved model evidence."""

        self._deterministic_constraints.extend(extraction.constraints)
        artifact.metadata.update(extraction.metadata)
        # A vendor-named directory/file is the strongest variant signal. If
        # none exists, a dialect required by structural parsing still denotes
        # a vendor-specific schema declaration set.
        if artifact.kind == "sql-ddl" and artifact.metadata.get(
            "db_schema_variant"
        ) == "default":
            parser_dialect = artifact.metadata.get("sql_parser_dialect")
            if parser_dialect and parser_dialect != "generic":
                self._set_db_schema_context(
                    artifact.metadata,
                    artifact.metadata.get("db_schema_module", "."),
                    parser_dialect,
                )
        for constraint in extraction.constraints:
            if constraint.layer == "schema":
                constraint.subject.schema_context_id = artifact.metadata.get(
                    "db_schema_context_id"
                )
        residuals = list(extraction.residuals)
        if artifact.truncated:
            truncation_note = (
                "The artifact was truncated. Inspect only the available "
                "declaration for constraints not listed as deterministic."
            )
            # Parser residuals already embed the available source. Repeating
            # artifact.content here previously doubled large SQL payloads.
            residuals.append(
                truncation_note
                if residuals
                else truncation_note + "\n" + artifact.content
            )
        artifact.llm_required = bool(residuals)
        if not residuals:
            artifact.llm_content = None
            artifact.metadata["extraction"] = "deterministic-complete"
            return

        known = [item.model_dump(mode="json") for item in extraction.constraints]
        artifact.llm_content = (
            "Only analyze the unresolved declarations below. Do not repeat the "
            "deterministically extracted constraints.\n\n"
            + "\n\n".join(residuals)
            + "\n\nDeterministically extracted constraints to exclude:\n"
            + json.dumps(known, indent=2, sort_keys=True)
        )
        artifact.metadata["extraction"] = "hybrid-residual"

    def _candidate_files(self) -> Iterable[Path]:
        allowed = {".sql", ".xml", ".yaml", ".yml", ".json"}
        for root, directories, files in os.walk(self.project_path):
            # Mutating directories in place prunes os.walk before it descends
            # into generated, dependency, or VCS content.
            directories[:] = [item for item in directories if item not in IGNORED_DIRECTORIES]
            root_path = Path(root)
            if not self.include_tests and self._is_test_path(self._display_path(root_path)):
                directories[:] = []
                continue
            for name in files:
                path = root_path / name
                if path.suffix.lower() in allowed:
                    yield path

    def _custom_constraint_names(self) -> set[str]:
        """Recover custom Bean Validation annotations CLDK may omit metadata for."""

        """
        Example of a custom constraint declaration:

        @Constraint(validatedBy = TenantCodeValidator.class)
        public @interface TenantCode {}

        @Entity
        class Account {
            @TenantCode
            String tenant;
        }

        The CLDK symbol table may not include the @Constraint meta-annotation
        on the TenantCode annotation, so we scan the source tree for any
        annotation declarations that contain "@interface" and "Constraint" in
        their annotations.
        """

        result: set[str] = set()
        pattern = re.compile(
            r"@(?:jakarta\.validation\.|javax\.validation\.)?Constraint\b"
            r"[\s\S]{0,2000}?@interface\s+([A-Za-z_$][\w$]*)"
        )
        for root, directories, files in os.walk(self.project_path):
            directories[:] = [item for item in directories if item not in IGNORED_DIRECTORIES]
            root_path = Path(root)
            if not self.include_tests and self._is_test_path(self._display_path(root_path)):
                directories[:] = []
                continue
            for name in files:
                if not name.endswith(".java"):
                    continue
                path = root_path / name
                try:
                    if path.stat().st_size > self.max_file_chars:
                        continue
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                result.update(match.group(1) for match in pattern.finditer(text))
        return result

    def _imports_by_file(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for unit in self.analysis.get_compilation_units():
            path = Path(unit.file_path)
            if not path.is_absolute():
                path = self.project_path / path
            result[str(path.resolve())] = list(unit.imports or [])
        return result

    def _java_file(self, qualified: str) -> Path | None:
        try:
            raw = self.analysis.get_java_file(qualified)
        except Exception:
            raw = None
        if not raw:
            return None
        path = Path(str(raw))
        return path if path.is_absolute() else self.project_path / path

    def _db_schema_context(self, path: Path) -> dict[str, str]:
        """Derive a stable module/vendor identity for one schema declaration.

        Migration files in the same build module and vendor directory belong
        to one declaration set. Vendor alternatives deliberately do not merge,
        even when they declare identically named tables.
        """

        module_path = self.project_path
        cursor = path.parent.resolve()
        build_markers = {
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
        }
        while cursor == self.project_path or self.project_path in cursor.parents:
            if any((cursor / marker).is_file() for marker in build_markers):
                module_path = cursor
                break
            if cursor == self.project_path:
                break
            cursor = cursor.parent
        try:
            module = module_path.relative_to(self.project_path).as_posix() or "."
        except ValueError:
            module = "."

        aliases = {
            "mysql": "mysql",
            "mariadb": "mariadb",
            "postgres": "postgresql",
            "postgresql": "postgresql",
            "pgsql": "postgresql",
            "h2": "h2",
            "hsqldb": "hsqldb",
            "oracle": "oracle",
            "sqlserver": "sqlserver",
            "mssql": "sqlserver",
            "sqlite": "sqlite",
            "derby": "derby",
            "db2": "db2",
        }
        relative = self._display_path(path).lower()
        tokens = re.findall(r"[a-z0-9]+", relative)
        variant = next((aliases[token] for token in reversed(tokens) if token in aliases), "default")
        metadata: dict[str, str] = {}
        self._set_db_schema_context(metadata, module, variant)
        return metadata

    @staticmethod
    def _liquibase_dbms(content: str, suffix: str) -> str | None:
        """Return a normalized, explicit change-set ``dbms`` selector."""

        try:
            if suffix == ".xml":
                raw = ElementTree.fromstring(content).attrib.get("dbms")
            else:
                value = json.loads(content) if suffix == ".json" else yaml.safe_load(content)

                def find_dbms(item: Any) -> Any:
                    if isinstance(item, dict):
                        change_set = item.get("changeSet")
                        if isinstance(change_set, dict) and change_set.get("dbms"):
                            return change_set["dbms"]
                        for child in item.values():
                            found = find_dbms(child)
                            if found:
                                return found
                    elif isinstance(item, list):
                        for child in item:
                            found = find_dbms(child)
                            if found:
                                return found
                    return None

                raw = find_dbms(value)
        except (ElementTree.ParseError, json.JSONDecodeError, yaml.YAMLError):
            return None
        if not raw:
            return None
        values = sorted(
            {
                item.strip().lower()
                for item in re.split(r"[,\s]+", str(raw))
                if item.strip()
            }
        )
        if not values or values == ["all"]:
            return None
        aliases = {"postgres": "postgresql", "pgsql": "postgresql", "mssql": "sqlserver"}
        if len(values) == 1 and not values[0].startswith("!"):
            return aliases.get(values[0], values[0])
        return "liquibase-dbms:" + ",".join(values)

    @staticmethod
    def _set_db_schema_context(
        metadata: dict[str, str], module: str, variant: str
    ) -> None:
        key = f"{module}|{variant}"
        metadata.update(
            {
                "db_schema_context_id": "dbctx-"
                + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12],
                "db_schema_context_key": key,
                "db_schema_context_label": (
                    variant if module == "." else f"{module} [{variant}]"
                ),
                "db_schema_module": module,
                "db_schema_variant": variant,
            }
        )

    def _artifact(
        self,
        kind: str,
        file_path: str,
        start_line: int | None,
        end_line: int | None,
        content: str,
        **values: Any,
    ) -> EvidenceArtifact:
        # Content-addressed IDs make unchanged evidence stable across runs and
        # allow extraction responses to be checked against a known citation.
        raw = "\0".join((kind, file_path, str(start_line), str(end_line), content))
        artifact_id = "pe-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return EvidenceArtifact(
            artifact_id=artifact_id,
            kind=kind,
            source=SourceLocation(
                file_path=file_path, start_line=start_line, end_line=end_line
            ),
            content=content,
            **values,
        )

    def _bound(self, content: str, file_path: str) -> tuple[str, bool]:
        if len(content) <= self.max_artifact_chars:
            return content, False
        self._warnings.append(
            f"Truncated evidence from {file_path} to {self.max_artifact_chars} characters."
        )
        marker = "\n... truncated by persistence evidence budget"
        return content[: self.max_artifact_chars - len(marker)] + marker, True

    def _display_path(self, path: Path | None) -> str:
        if path is None:
            return "<unknown>"
        try:
            return str(path.resolve().relative_to(self.project_path))
        except ValueError:
            return str(path.resolve())

    @staticmethod
    def _annotation_names(annotations: list[str] | None) -> set[str]:
        return {parse_annotation(item).name for item in annotations or []}

    @staticmethod
    def _mapped_kind(java_type: Any) -> str:
        names = PersistenceEvidencePreparer._annotation_names(java_type.annotations)
        return next((name for name in ("Entity", "MappedSuperclass", "Embeddable") if name in names), "mapped")

    @staticmethod
    def _relevant_import(imported: str) -> bool:
        return imported.startswith((
            "jakarta.persistence", "javax.persistence", "org.hibernate.annotations",
            "jakarta.validation", "javax.validation",
        ))

    @staticmethod
    def _find_type_line(path: Path | None, simple_name: str) -> int | None:
        if path is None:
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        match = re.search(rf"\b(?:class|interface|record|enum)\s+{re.escape(simple_name)}\b", text)
        return PersistenceEvidencePreparer._line_at(text, match.start()) if match else None

    @staticmethod
    def _looks_like_liquibase(suffix: str, text: str) -> bool:
        """Recognize a changelog from parsed document structure, not markers."""

        try:
            if suffix == ".xml":
                root = ElementTree.fromstring(text)
                return (
                    PersistenceEvidencePreparer._local_name(root.tag)
                    == "databaseChangeLog"
                    and any(
                        PersistenceEvidencePreparer._local_name(element.tag)
                        == "changeSet"
                        for element in root.iter()
                    )
                )
            data = json.loads(text) if suffix == ".json" else yaml.safe_load(text)
        except (
            ElementTree.ParseError,
            json.JSONDecodeError,
            yaml.YAMLError,
            TypeError,
            ValueError,
        ):
            return False
        return (
            isinstance(data, dict)
            and "databaseChangeLog" in data
            and any(
                True
                for _ in PersistenceEvidencePreparer._json_changesets(
                    data["databaseChangeLog"]
                )
            )
        )

    @staticmethod
    def _json_changesets(value: Any) -> Iterable[Any]:
        # Liquibase permits wrapper objects and lists at several nesting levels.
        if isinstance(value, dict):
            if "changeSet" in value:
                yield value
            else:
                for child in value.values():
                    yield from PersistenceEvidencePreparer._json_changesets(child)
        elif isinstance(value, list):
            for child in value:
                yield from PersistenceEvidencePreparer._json_changesets(child)

    @staticmethod
    def _yaml_changeset_nodes(node: Node | None) -> Iterable[MappingNode]:
        if isinstance(node, MappingNode):
            for key, value in node.value:
                if isinstance(key, ScalarNode) and key.value == "changeSet":
                    yield node
                else:
                    yield from PersistenceEvidencePreparer._yaml_changeset_nodes(value)
        elif isinstance(node, SequenceNode):
            for child in node.value:
                yield from PersistenceEvidencePreparer._yaml_changeset_nodes(child)

    @staticmethod
    def _xml_changeset_lines(text: str) -> list[tuple[int, int]]:
        handler = _ChangeSetLineHandler()
        try:
            parser = make_parser()
            parser.setFeature(feature_namespaces, True)
            parser.setContentHandler(handler)
            parser.parse(StringIO(text))
        except SAXException:
            # ElementTree already validated the document. Line numbers are
            # optional provenance, so a SAX implementation failure must not
            # discard otherwise valid change-set evidence.
            return []
        return handler.ranges

    @staticmethod
    def _local_name(name: str) -> str:
        return name.rsplit("}", 1)[-1].rsplit(":", 1)[-1]

    @staticmethod
    def _is_constraint_ddl(statement: str) -> bool:
        """Classify parsed generic SQL, retaining failures via lexical fallback."""

        try:
            expression = sqlglot.parse_one(
                statement, error_level=sqlglot.ErrorLevel.RAISE
            )
        except SqlglotError:
            return bool(DDL_FALLBACK_PATTERN.search(statement))
        expressions = (
            expression.expressions
            if isinstance(expression, exp.Block)
            else [expression]
        )
        for candidate in expressions:
            if isinstance(candidate, exp.Create) and (
                candidate.kind == "TABLE"
                or (
                    candidate.kind == "INDEX"
                    and bool(candidate.args.get("unique"))
                )
            ):
                return True
            if isinstance(candidate, exp.Alter) and candidate.kind == "TABLE":
                return True
            if isinstance(candidate, exp.Command) and DDL_FALLBACK_PATTERN.search(
                candidate.sql()
            ):
                return True
        return False

    @staticmethod
    def _split_sql(text: str) -> Iterable[tuple[str, int, int]]:
        # The generic SQLGlot tokenizer recognizes quoted strings and comments,
        # so semicolons are statement boundaries only when they are SQL tokens.
        # UNKNOWN tokens indicate unsupported or dialect-specific syntax, but
        # their offsets and surrounding semicolon tokens are still valid. Keep
        # splitting so one dialect feature cannot collapse a whole file into a
        # single residual artifact.
        try:
            tokens = Tokenizer().tokenize(text)
        except SqlglotError:
            if text.strip():
                yield text, 1, text.count("\n") + 1
            return

        start: int | None = None
        for token in tokens:
            if start is None:
                start = token.start
            if token.token_type != TokenType.SEMICOLON:
                continue
            statement = text[start:token.end + 1]
            if statement.strip():
                yield (
                    statement,
                    PersistenceEvidencePreparer._line_at(text, start),
                    token.line,
                )
            start = None
        if start is not None:
            tail = text[start:]
            if tail.strip():
                yield (
                    tail,
                    PersistenceEvidencePreparer._line_at(text, start),
                    text.count("\n") + 1,
                )

    @staticmethod
    def _line_at(text: str, offset: int) -> int:
        return text.count("\n", 0, max(0, offset)) + 1

    @staticmethod
    def _is_test_path(path: str) -> bool:
        parts = Path(path.replace("\\", "/")).parts
        return any(parts[index:index + 2] == ("src", "test") for index in range(len(parts) - 1))
