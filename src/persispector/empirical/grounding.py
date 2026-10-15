"""Build bounded, statically grounded source evidence for an IPD."""

from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cldk.analysis.java import JavaAnalysis
from hamster.code_analysis.common.java_analyzer import Reachability

from persispector.empirical.models import (
    CodeEvidence,
    EvidenceBundle,
    IPDRecord,
    OperationMatch,
    PersistenceHint,
)
from persispector.operations import JavaApiOperation, JavaOperationIndex

DSL_WORDS = {
    "if", "then", "and", "or", "onlyone", "zeroorone", "required",
    "true", "false", "null", "none", "not", "xor",
}


@dataclass(frozen=True)
class _MethodRef:
    qualified_class: str
    callable: Any
    file_path: str

    @property
    def key(self) -> tuple[str, str]:
        return self.qualified_class, self.callable.signature

    @property
    def symbol(self) -> str:
        return f"{self.qualified_class}#{self.callable.signature}"


class SourceEvidenceBuilder:
    """Resolve an operation, follow its calls, and expose persistence candidates."""

    def __init__(
        self,
        analysis: JavaAnalysis,
        project_path: str | Path,
        *,
        max_depth: int = 4,
        max_methods: int = 30,
        max_total_chars: int = 48_000,
        max_method_chars: int = 8_000,
    ):
        self.analysis = analysis
        self.project_path = str(Path(project_path).resolve())
        self.max_depth = max_depth
        self.max_methods = max_methods
        self.max_total_chars = max_total_chars
        self.max_method_chars = max_method_chars
        self.operation_index = JavaOperationIndex(analysis)
        self.reachability = Reachability(analysis)
        self.classes = analysis.get_classes()
        self.methods = self._index_methods()
        self.crud_operations = self._index_crud_operations()

    def build(self, record: IPDRecord) -> EvidenceBundle:
        dependency_parameters = extract_dependency_parameters(record.dependency)
        operations = self.operation_index.find(record.path, record.http_method)
        operation_matches: list[OperationMatch] = []
        seeds: list[tuple[_MethodRef, str]] = []

        if operations:
            exact = any(
                self.operation_index.normalize_path(operation.path)
                == self.operation_index.normalize_path(record.path)
                for operation in operations
            )
            resolution = "exact" if exact else "path-template"
            if len(operations) > 1:
                resolution = "ambiguous"
            for operation in operations:
                operation_matches.append(
                    self._operation_match(record, operation, resolution)
                )
                seeds.append((self._method_ref(operation.qualified_class, operation.callable), "endpoint"))
        else:
            operation_matches.append(
                OperationMatch(
                    resolution="not-found",
                    requested_path=record.path,
                    requested_method=record.http_method,
                )
            )

        reached, unresolved = self._reachable_methods(seeds)
        reached = self._add_parameter_mentions(reached, dependency_parameters)
        evidence = self._make_evidence(reached, dependency_parameters)
        hints = self._persistence_hints(evidence, reached, dependency_parameters)
        warnings: list[str] = []
        if not seeds:
            warnings.append("No endpoint callable was resolved; evidence is lexical only.")
        if not hints:
            warnings.append(
                "CLDK reported no CRUD operation in the collected evidence."
            )
        if any(item.truncated for item in evidence):
            warnings.append("One or more source snippets were truncated to the configured budget.")

        return EvidenceBundle(
            case=record,
            case_id=record.case_id,
            project_path=self.project_path,
            dependency_parameters=dependency_parameters,
            operation_matches=operation_matches,
            code_evidence=evidence,
            persistence_hints=hints,
            unresolved_calls=unresolved[:100],
            warnings=warnings,
        )

    def _index_methods(self) -> dict[tuple[str, str], _MethodRef]:
        result: dict[tuple[str, str], _MethodRef] = {}
        for qualified, java_type in self.classes.items():
            try:
                file_path = str(self.analysis.get_java_file(qualified) or "")
            except Exception:
                file_path = ""
            for java_callable in (java_type.callable_declarations or {}).values():
                if not java_callable.is_constructor:
                    ref = _MethodRef(qualified, java_callable, file_path)
                    result[ref.key] = ref
        return result

    def _index_crud_operations(self) -> dict[tuple[str, str], list[Any]]:
        result: dict[tuple[str, str], list[Any]] = {}
        for record in self.analysis.get_all_crud_operations():
            qualified_class = next(
                (key for key in record if key in self.classes),
                None,
            )
            java_callable = next(
                (
                    value
                    for key, value in record.items()
                    if key != "crud_operations" and hasattr(value, "signature")
                ),
                None,
            )
            operations = [
                operation
                for operation in record.get("crud_operations", [])
                if operation.operation_type is not None
            ]
            if qualified_class and java_callable is not None and operations:
                result[(qualified_class, java_callable.signature)] = operations
        return result

    def _operation_match(
        self, record: IPDRecord, operation: JavaApiOperation, resolution: str
    ) -> OperationMatch:
        return OperationMatch(
            resolution=resolution,  # type: ignore[arg-type]
            requested_path=record.path,
            requested_method=record.http_method.upper(),
            resolved_path=operation.path,
            symbol=operation.symbol,
            file_path=operation.file_path,
            start_line=operation.start_line,
            end_line=operation.end_line,
            operation_parameters=list(operation.parameter_names),
        )

    def _method_ref(self, qualified: str, java_callable: Any) -> _MethodRef:
        return self.methods.get(
            (qualified, java_callable.signature),
            _MethodRef(qualified, java_callable, ""),
        )

    def _reachable_methods(
        self, seeds: list[tuple[_MethodRef, str]]
    ) -> tuple[list[tuple[_MethodRef, int, str]], list[str]]:
        queue = deque((ref, 0, kind) for ref, kind in seeds)
        seen: set[tuple[str, str]] = set()
        reached: list[tuple[_MethodRef, int, str]] = []
        unresolved: list[str] = []
        while queue and len(reached) < self.max_methods:
            ref, depth, kind = queue.popleft()
            if ref.key in seen:
                continue
            seen.add(ref.key)
            reached.append((ref, depth, kind))
            if depth >= self.max_depth:
                continue
            targets, missing = self._callee_targets(ref)
            unresolved.extend(missing)
            for target in targets:
                queue.append((target, depth + 1, "reachable-method"))
        return reached, unresolved

    def _callee_targets(
        self, caller: _MethodRef
    ) -> tuple[list[_MethodRef], list[str]]:
        cldk_targets = self._cldk_callees(caller)
        if cldk_targets:
            return cldk_targets, []

        targets: dict[tuple[str, str], _MethodRef] = {}
        unresolved: list[str] = []
        for call_site in caller.callable.call_sites or []:
            fallback_targets = self._resolve_call_site(caller, call_site)
            if fallback_targets:
                targets.update((target.key, target) for target in fallback_targets)
            elif self._looks_application_call(call_site):
                unresolved.append(
                    f"{caller.symbol} -> {call_site.receiver_type}#"
                    f"{call_site.callee_signature or call_site.method_name}"
                )

        return list(targets.values()), unresolved

    def _cldk_callees(self, caller: _MethodRef) -> list[_MethodRef] | None:
        try:
            result = self.analysis.get_callees(
                source_class_name=caller.qualified_class,
                source_method_declaration=caller.callable.signature,
                using_symbol_table=True,
            )
        except Exception:
            return None

        targets: list[_MethodRef] = []
        for details in result.get("callee_details", []):
            method_detail = details.get("callee_method")
            if method_detail is None or method_detail.klass not in self.classes:
                continue
            targets.append(
                self._method_ref(method_detail.klass, method_detail.method)
            )
        return list({target.key: target for target in targets}.values())

    def _resolve_call_site(
        self, caller: _MethodRef, call_site: Any
    ) -> list[_MethodRef]:
        """Best-effort fallback when CLDK has no matching call-graph edge."""

        receiver = (call_site.receiver_type or "").split("<", 1)[0]
        owners: list[str] = []
        if receiver in self.classes:
            owners.append(receiver)
        elif receiver:
            simple = receiver.rsplit(".", 1)[-1]
            matches = [name for name in self.classes if name.rsplit(".", 1)[-1] == simple]
            if len(matches) == 1:
                owners.extend(matches)
        else:
            owners.append(caller.qualified_class)

        signature = call_site.callee_signature or ""
        result: list[_MethodRef] = []
        for owner in owners:
            direct = self.methods.get((owner, signature)) if signature else None
            if direct:
                result.append(direct)
                continue
            if signature:
                try:
                    inherited = self.reachability.find_method_in_hierarchy(owner, signature)
                except Exception:
                    inherited = None
                if inherited:
                    for ref in self.methods.values():
                        if ref.callable is inherited:
                            result.append(ref)
                            break
            if not result:
                for ref in self.methods.values():
                    if ref.qualified_class != owner:
                        continue
                    if ref.callable.signature.split("(", 1)[0] == call_site.method_name:
                        result.append(ref)
        return list({ref.key: ref for ref in result}.values())

    def _add_parameter_mentions(
        self,
        reached: list[tuple[_MethodRef, int, str]],
        parameters: list[str],
    ) -> list[tuple[_MethodRef, int, str]]:
        existing = {ref.key for ref, _, _ in reached}
        candidates: list[tuple[int, _MethodRef]] = []
        for ref in self.methods.values():
            if ref.key in existing or self._is_test_file(ref.file_path):
                continue
            code = self._method_source(ref.callable)
            mentions = sum(bool(re.search(rf"\b{re.escape(name)}\b", code)) for name in parameters)
            if mentions:
                candidates.append((mentions + self._persistence_score(ref), ref))
        candidates.sort(key=lambda item: (-item[0], item[1].symbol))
        remaining = max(0, self.max_methods - len(reached))
        reached.extend((ref, -1, "parameter-mention") for _, ref in candidates[: min(8, remaining)])
        return reached

    def _make_evidence(
        self,
        reached: list[tuple[_MethodRef, int, str]],
        parameters: list[str],
    ) -> list[CodeEvidence]:
        result: list[CodeEvidence] = []
        remaining = self.max_total_chars
        for ref, depth, seed_kind in reached:
            if remaining <= 0:
                break
            source = self._method_source(ref.callable)
            allowed = min(remaining, self.max_method_chars)
            truncated = len(source) > allowed
            code = source[:allowed]
            if truncated:
                code += "\n// ... truncated by evidence budget"
            remaining -= len(code)
            persistence_score = self._persistence_score(ref)
            kind = seed_kind
            if seed_kind == "reachable-method" and persistence_score:
                kind = "persistence-method"
            mentioned = [
                name for name in parameters if re.search(rf"\b{re.escape(name)}\b", source)
            ]
            relevance = [f"mentions parameter {name}" for name in mentioned]
            if persistence_score:
                relevance.append("contains CLDK-classified CRUD operations")
            evidence_id = self._evidence_id("code", ref.symbol, str(ref.callable.start_line))
            result.append(
                CodeEvidence(
                    evidence_id=evidence_id,
                    kind=kind,  # type: ignore[arg-type]
                    symbol=ref.symbol,
                    file_path=ref.file_path,
                    start_line=ref.callable.start_line,
                    end_line=ref.callable.end_line,
                    code=code,
                    depth=None if depth < 0 else depth,
                    relevance=relevance,
                    truncated=truncated,
                )
            )
        return result

    def _persistence_hints(
        self,
        evidence: list[CodeEvidence],
        reached: list[tuple[_MethodRef, int, str]],
        parameters: list[str],
    ) -> list[PersistenceHint]:
        evidence_by_symbol = {item.symbol: item for item in evidence}
        hints: list[PersistenceHint] = []
        for ref, _, _ in reached:
            if ref.symbol not in evidence_by_symbol:
                continue
            for operation in self.crud_operations.get(ref.key, []):
                kind = operation.operation_type.value.lower()
                line = operation.line_number
                expression = self._crud_expression(ref, line)
                related = [
                    name
                    for name in parameters
                    if re.search(rf"\b{re.escape(name)}\b", expression)
                ]
                hints.append(
                    PersistenceHint(
                        evidence_id=self._evidence_id(
                            "cldk-crud",
                            ref.symbol,
                            str(line),
                            kind,
                            expression,
                        ),
                        kind=kind,  # type: ignore[arg-type]
                        symbol=ref.symbol,
                        file_path=ref.file_path,
                        line=line,
                        expression=expression,
                        related_parameters=related,
                        basis=(
                            "CLDK codeanalyzer classified this source line as "
                            f"a {operation.operation_type.value} operation."
                        ),
                    )
                )
        return list({hint.evidence_id: hint for hint in hints}.values())

    def _persistence_score(self, ref: _MethodRef) -> int:
        return min(3, len(self.crud_operations.get(ref.key, [])))

    def _crud_expression(self, ref: _MethodRef, line: int) -> str:
        call_site = next(
            (
                site
                for site in ref.callable.call_sites or []
                if site.start_line == line and site.crud_operation is not None
            ),
            None,
        )
        if call_site is not None:
            return self._call_expression(call_site)
        if line == ref.callable.start_line:
            return ref.callable.declaration
        code_lines = (ref.callable.code or "").splitlines()
        index = line - ref.callable.code_start_line
        if 0 <= index < len(code_lines):
            return code_lines[index].strip()
        return ref.callable.declaration

    @staticmethod
    def _call_expression(call_site: Any) -> str:
        receiver = f"{call_site.receiver_expr}." if call_site.receiver_expr else ""
        return f"{receiver}{call_site.method_name}({', '.join(call_site.argument_expr or [])})"

    @staticmethod
    def _looks_application_call(call_site: Any) -> bool:
        receiver = call_site.receiver_type or ""
        return bool(receiver and not receiver.startswith(("java.", "javax.", "jakarta.", "org.springframework.")))

    @staticmethod
    def _method_source(java_callable: Any) -> str:
        return f"{java_callable.declaration}\n{java_callable.code}".strip()

    @staticmethod
    def _evidence_id(*parts: str) -> str:
        value = "\0".join(parts)
        return "ev-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _is_test_file(path: str) -> bool:
        normalized = path.replace("\\", "/")
        return "/src/test/" in normalized or normalized.endswith("Test.java")


def extract_dependency_parameters(dependency: str) -> list[str]:
    """Extract identifier-like parameter names from the supplied IPD DSL."""

    without_strings = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", " ", dependency)
    function_names = {
        match.group(1).lower()
        for match in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(", without_strings)
    }
    result: list[str] = []
    for token in re.findall(r"\b[A-Za-z_$][\w$]*\b", without_strings):
        lower = token.lower()
        if lower in DSL_WORDS or lower in function_names:
            continue
        if token not in result:
            result.append(token)
    return result
