"""Public index from HTTP method/path pairs to CLDK Java callables."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from persispector.generator import OpenAPIGenerator


@dataclass(frozen=True)
class JavaApiParameter:
    """Transport parameter or request-body leaf exposed by an operation."""

    name: str
    location: str
    path: tuple[str, ...]
    required: bool = False
    schema_type: str | None = None


@dataclass(frozen=True)
class JavaApiOperation:
    """A resolved API operation and the Java callable implementing it."""

    path: str
    http_method: str
    qualified_class: str
    method_signature: str
    file_path: str
    start_line: int
    end_line: int
    parameter_names: tuple[str, ...]
    callable: Any
    parameter_details: tuple[JavaApiParameter, ...] = ()
    locator_chain: tuple[tuple[str, str], ...] = ()

    @property
    def symbol(self) -> str:
        return f"{self.qualified_class}#{self.method_signature}"

    @property
    def source(self) -> str:
        return f"{self.callable.declaration} {self.callable.code}".strip()


class JavaOperationIndex:
    """Resolve an API operation to source using Persispector's route analysis."""

    def __init__(self, analysis: Any):
        self.analysis = analysis
        self._generator = OpenAPIGenerator(analysis)
        self.operations = self._build()

    def find(self, path: str, http_method: str) -> list[JavaApiOperation]:
        method = http_method.lower()
        exact_path = self.normalize_path(path)
        exact = [
            operation
            for operation in self.operations
            if operation.http_method == method
            and self.normalize_path(operation.path) == exact_path
        ]
        if exact:
            return exact
        template = self.template_path(path)
        return [
            operation
            for operation in self.operations
            if operation.http_method == method
            and self.template_path(operation.path) == template
        ]

    def _build(self) -> list[JavaApiOperation]:
        self._generator._discover_resources()
        result: list[JavaApiOperation] = []
        application_paths = self._generator._application_paths()
        for resource in self._generator.resources.values():
            global_prefixes = application_paths if resource.framework == "jaxrs" else [""]
            for java_callable, mapping in resource.methods:
                for prefix, locator_chain in self._generator._resource_routes(
                    resource.qualified_name, set()
                ):
                    inherited_parameters: list[dict[str, Any]] = []
                    for parent, locator, locator_mapping in locator_chain:
                        parameters, _ = self._generator._parameters(
                            parent, locator, locator_mapping
                        )
                        inherited_parameters.extend(parameters)
                    own_parameters, request_body = self._generator._parameters(
                        resource, java_callable, mapping
                    )
                    transport_parameters = inherited_parameters + own_parameters
                    try:
                        file_path = self.analysis.get_java_file(resource.qualified_name)
                    except Exception:
                        file_path = getattr(java_callable, "file_path", "") or ""
                    for global_prefix in global_prefixes:
                        for method_path in mapping.paths or [""]:
                            path = self._generator._join_path(
                                global_prefix, prefix, method_path
                            )[0]
                            parameter_details = self._parameter_details(
                                path, transport_parameters, request_body
                            )
                            # Preserve the historical parameter_names contract:
                            # it contains OpenAPI path/query/header/cookie/form
                            # names, while body leaves are available through the
                            # richer parameter_details field.
                            parameter_names = tuple(
                                dict.fromkeys(
                                    item.name
                                    for item in parameter_details
                                    if item.location != "body"
                                )
                            )
                            for http_method in mapping.methods:
                                result.append(
                                    JavaApiOperation(
                                        path=path,
                                        http_method=http_method,
                                        qualified_class=resource.qualified_name,
                                        method_signature=java_callable.signature,
                                        file_path=str(file_path or ""),
                                        start_line=java_callable.start_line,
                                        end_line=java_callable.end_line,
                                        parameter_names=parameter_names,
                                        parameter_details=parameter_details,
                                        callable=java_callable,
                                        locator_chain=tuple(
                                            (parent.qualified_name, locator.signature)
                                            for parent, locator, _ in locator_chain
                                        ),
                                    )
                                )
        return result

    def _parameter_details(
        self,
        path: str,
        parameters: list[dict[str, Any]],
        request_body: dict[str, Any] | None,
    ) -> tuple[JavaApiParameter, ...]:
        """Retain transport names and flatten request-body object leaves."""

        result: list[JavaApiParameter] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()
        for parameter in parameters:
            name = str(parameter.get("name") or "parameter")
            location = str(parameter.get("in") or "unknown")
            key = (location, (name,))
            if key in seen:
                continue
            seen.add(key)
            schema = parameter.get("schema") or {}
            result.append(
                JavaApiParameter(
                    name=name,
                    location=location,
                    path=(name,),
                    required=bool(parameter.get("required")),
                    schema_type=self._schema_type(schema),
                )
            )

        # OpenAPI permits a path template even when no explicit Java parameter
        # annotation was recovered. Keep that externally visible name.
        for name in re.findall(r"\{([^{}]+)\}", path):
            key = ("path", (name,))
            if key in seen:
                continue
            seen.add(key)
            result.append(
                JavaApiParameter(
                    name=name,
                    location="path",
                    path=(name,),
                    required=True,
                    schema_type="string",
                )
            )

        if request_body:
            content = request_body.get("content") or {}
            body_schema = next(
                (
                    item.get("schema")
                    for item in content.values()
                    if isinstance(item, dict) and item.get("schema")
                ),
                None,
            )
            media_types = {str(item).lower() for item in content}
            location = (
                "form"
                if media_types
                & {
                    "application/x-www-form-urlencoded",
                    "multipart/form-data",
                }
                else "body"
            )
            if isinstance(body_schema, dict):
                result.extend(
                    self._body_leaves(
                        body_schema,
                        path=(location,),
                        location=location,
                        required=bool(request_body.get("required")),
                        seen_refs=set(),
                    )
                )

        unique = {
            (item.location, item.path, item.name): item for item in result
        }
        return tuple(
            sorted(
                unique.values(),
                key=lambda item: (item.location, item.path, item.name),
            )
        )

    def _body_leaves(
        self,
        schema: dict[str, Any],
        *,
        path: tuple[str, ...],
        location: str,
        required: bool,
        seen_refs: set[str],
    ) -> list[JavaApiParameter]:
        reference = schema.get("$ref")
        if isinstance(reference, str):
            name = reference.rsplit("/", 1)[-1]
            if name in seen_refs:
                return []
            component = self._generator.schemas.components.get(name)
            if component:
                return self._body_leaves(
                    component,
                    path=path,
                    location=location,
                    required=required,
                    seen_refs={*seen_refs, name},
                )

        if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
            return self._body_leaves(
                schema["items"],
                path=path,
                location=location,
                required=required,
                seen_refs=seen_refs,
            )

        properties = schema.get("properties")
        if isinstance(properties, dict) and properties:
            required_names = set(schema.get("required") or [])
            result: list[JavaApiParameter] = []
            for name, child in properties.items():
                if not isinstance(child, dict):
                    continue
                result.extend(
                    self._body_leaves(
                        child,
                        path=(*path, str(name)),
                        location=location,
                        # A required request body does not make every object
                        # property required. Only a schema-local required list
                        # can establish that for the leaf.
                        required=name in required_names,
                        seen_refs=seen_refs,
                    )
                )
            return result

        # Only named leaves are useful for persistence-name matching. An opaque
        # object or scalar body whose Java parameter name was lost is omitted.
        if len(path) < 2:
            return []
        return [
            JavaApiParameter(
                name=path[-1],
                location=location,
                path=path,
                required=required,
                schema_type=self._schema_type(schema),
            )
        ]

    @staticmethod
    def _schema_type(schema: dict[str, Any]) -> str | None:
        if "$ref" in schema:
            return str(schema["$ref"]).rsplit("/", 1)[-1]
        value = schema.get("type")
        return str(value) if value else None

    @staticmethod
    def normalize_path(path: str) -> str:
        normalized = "/" + "/".join(part for part in path.split("/") if part)
        return normalized if normalized != "" else "/"

    @classmethod
    def template_path(cls, path: str) -> str:
        normalized = cls.normalize_path(path)
        return re.sub(r"\{[^{}]+\}", "{}", normalized)
