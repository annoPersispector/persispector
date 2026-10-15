"""Generate OpenAPI documents from Java source using CLDK and Hamster."""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from typing import Any, Iterable

from cldk import CLDK
from cldk.analysis import AnalysisLevel

from persispector.annotations import JavaAnnotation, parse_annotations
from persispector.schemas import SchemaBuilder, parse_java_type


logger = logging.getLogger(__name__)

SPRING_ANNOTATION_IMPORT = "org.springframework.web.bind.annotation"
JAX_RS_ANNOTATION_IMPORTS = ("javax.ws.rs", "jakarta.ws.rs")
SPRING_MAPPINGS = {
    "GetMapping": ("get",), "PostMapping": ("post",), "PutMapping": ("put",),
    "DeleteMapping": ("delete",), "PatchMapping": ("patch",),
}
JAX_METHODS = {name: name.lower() for name in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")}
SPRING_PARAMETERS = {
    "PathVariable": "path", "RequestParam": "query", "RequestHeader": "header",
    "CookieValue": "cookie", "MatrixVariable": "path",
}
JAX_PARAMETERS = {
    "PathParam": "path", "QueryParam": "query", "HeaderParam": "header",
    "CookieParam": "cookie", "MatrixParam": "path", "FormParam": "form",
}
ALL_SPRING_METHODS = ("get", "post", "head", "options", "put", "patch", "delete", "trace")

STATUS_ALIASES = {status.name: status.value for status in HTTPStatus}
STATUS_ALIASES.update({
    "CHECKPOINT": 103, "UNPROCESSABLE_ENTITY": 422, "I_AM_A_TEAPOT": 418,
    "MOVED_TEMPORARILY": 302, "METHOD_FAILURE": 420,
})
BUILDER_STATUSES = {
    "ok": 200, "created": 201, "accepted": 202, "noContent": 204,
    "notModified": 304, "seeOther": 303, "temporaryRedirect": 307,
    "badRequest": 400, "unauthorized": 401, "forbidden": 403, "notFound": 404,
    "unprocessableEntity": 422, "serverError": 500,
}
STATUS_DESCRIPTIONS = {str(status.value): status.phrase for status in HTTPStatus}
MEDIA_TYPE_CONSTANTS = {
    "APPLICATION_JSON": "application/json", "APPLICATION_JSON_VALUE": "application/json",
    "APPLICATION_XML": "application/xml", "APPLICATION_XML_VALUE": "application/xml",
    "TEXT_PLAIN": "text/plain", "TEXT_PLAIN_VALUE": "text/plain",
    "TEXT_HTML": "text/html", "TEXT_HTML_VALUE": "text/html",
    "APPLICATION_FORM_URLENCODED": "application/x-www-form-urlencoded",
    "APPLICATION_FORM_URLENCODED_VALUE": "application/x-www-form-urlencoded",
    "MULTIPART_FORM_DATA": "multipart/form-data", "MULTIPART_FORM_DATA_VALUE": "multipart/form-data",
    "APPLICATION_OCTET_STREAM": "application/octet-stream",
    "APPLICATION_OCTET_STREAM_VALUE": "application/octet-stream",
    "TEXT_EVENT_STREAM": "text/event-stream", "TEXT_EVENT_STREAM_VALUE": "text/event-stream",
}


@dataclass
class Mapping:
    paths: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    produces: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)


@dataclass
class Resource:
    qualified_name: str
    java_type: Any
    framework: str
    paths: list[str]
    produces: list[str]
    consumes: list[str]
    methods: list[tuple[Any, Mapping]] = field(default_factory=list)
    locators: list[tuple[Any, Mapping]] = field(default_factory=list)


class OpenAPIGenerator:
    """Extract Spring MVC and JAX-RS endpoints without symbolic execution."""

    def __init__(self, analysis: Any, *, title: str = "Generated API", version: str = "0.0.0"):
        self.analysis = analysis
        self.title = title
        self.version = version
        self.schemas = SchemaBuilder(analysis)
        self.resources: dict[str, Resource] = {}
        self._operation_ids: set[str] = set()
        self.framework = self._detect_project_framework()
        self.constants = self._build_constant_table()

    @classmethod
    def from_project(
        cls,
        project_path: str | Path,
        *,
        title: str | None = None,
        version: str = "0.0.0",
        analysis_json_path: str | Path | None = None,
        eager: bool = False,
    ) -> "OpenAPIGenerator":
        path = Path(project_path).resolve()
        analysis = CLDK(language="java").analysis(
            project_path=path,
            analysis_level=AnalysisLevel.symbol_table,
            analysis_json_path=analysis_json_path,
            eager=eager,
        )
        return cls(analysis, title=title or path.name, version=version)

    @classmethod
    def from_source(
        cls, source_code: str, *, title: str = "Generated API", version: str = "0.0.0"
    ) -> "OpenAPIGenerator":
        analysis = CLDK(language="java").analysis(
            source_code=source_code, analysis_level=AnalysisLevel.symbol_table
        )
        return cls(analysis, title=title, version=version)

    def generate(self) -> dict[str, Any]:
        self._operation_ids.clear()
        self._discover_resources()
        document: dict[str, Any] = {
            "openapi": "3.0.3",
            "info": {"title": self.title, "version": self.version},
            "paths": {},
        }
        for resource in self.resources.values():
            global_prefixes = self._application_paths() if resource.framework == "jaxrs" else [""]
            for method, mapping in resource.methods:
                routes = self._resource_routes(resource.qualified_name, set())
                for prefix, locator_chain in routes:
                    inherited_parameters: list[dict[str, Any]] = []
                    for parent_resource, locator, locator_mapping in locator_chain:
                        locator_parameters, _ = self._parameters(parent_resource, locator, locator_mapping)
                        inherited_parameters.extend(locator_parameters)
                    for global_prefix in global_prefixes:
                        for method_path in mapping.paths or [""]:
                            path, regexes = self._join_path(global_prefix, prefix, method_path)
                            for http_method in mapping.methods:
                                operation = self._operation(
                                    resource, method, mapping, path, regexes, http_method,
                                    inherited_parameters,
                                )
                                existing = document["paths"].setdefault(path, {})
                                if http_method not in existing:
                                    existing[http_method] = operation
        document["paths"] = dict(sorted(document["paths"].items()))
        if self.schemas.components:
            document["components"] = {"schemas": dict(sorted(self.schemas.components.items()))}
        return document

    def _discover_resources(self) -> None:
        self.resources.clear()
        if self.framework is None:
            return
        for qualified, java_type in self.analysis.get_classes().items():
            class_annotations = self._annotations(java_type.annotations)
            class_mapping = self._class_mapping(class_annotations, self.framework)
            resource = Resource(
                qualified, java_type, self.framework, class_mapping.paths or [""],
                class_mapping.produces, class_mapping.consumes,
            )
            for method in (java_type.callable_declarations or {}).values():
                if method.is_constructor:
                    continue
                mapping = self._method_mapping(
                    self._annotations(method.annotations),
                    self.framework,
                )
                if mapping.methods:
                    resource.methods.append((method, mapping))
                elif self.framework == "jaxrs" and mapping.paths:
                    resource.locators.append((method, mapping))
            if resource.methods or resource.locators:
                self.resources[qualified] = resource

    @staticmethod
    def _framework_signals(imports: Iterable[str]) -> tuple[bool, bool]:
        normalized = {item.strip().removesuffix(".*") for item in imports}
        spring = any(
            OpenAPIGenerator._direct_package_import(
                item,
                SPRING_ANNOTATION_IMPORT,
            )
            for item in normalized
        )
        jaxrs = any(
            OpenAPIGenerator._direct_package_import(item, root)
            for item in normalized
            for root in JAX_RS_ANNOTATION_IMPORTS
        )
        return spring, jaxrs

    @staticmethod
    def _direct_package_import(imported: str, package: str) -> bool:
        if imported == package:
            return True
        if imported.startswith(f"{package}."):
            remainder = imported[len(package) + 1 :]
            return "." not in remainder
        return False

    def _detect_project_framework(self) -> str | None:
        imports = (
            imported
            for unit in self.analysis.get_compilation_units()
            for imported in unit.imports
        )
        spring, jaxrs = self._framework_signals(imports)
        if spring and jaxrs:
            logger.warning(
                "Project imports both Spring Web and JAX-RS annotations; "
                "endpoint extraction is skipped because one framework is "
                "required for the whole project"
            )
            return None
        return "spring" if spring else "jaxrs" if jaxrs else None

    @staticmethod
    def _class_mapping(annotations: list[JavaAnnotation], framework: str) -> Mapping:
        result = Mapping()
        for annotation in annotations:
            if framework == "spring" and annotation.name == "RequestMapping":
                result.paths.extend(annotation.values("path", "value"))
                result.produces.extend(annotation.values("produces"))
                result.consumes.extend(annotation.values("consumes"))
            elif framework == "jaxrs":
                if annotation.name == "Path":
                    result.paths.extend(annotation.values("value"))
                elif annotation.name == "Produces":
                    result.produces.extend(annotation.values("value"))
                elif annotation.name == "Consumes":
                    result.consumes.extend(annotation.values("value"))
        return result

    @staticmethod
    def _method_mapping(annotations: list[JavaAnnotation], framework: str) -> Mapping:
        result = Mapping()
        for annotation in annotations:
            if framework == "spring":
                if annotation.name in SPRING_MAPPINGS:
                    result.methods.extend(SPRING_MAPPINGS[annotation.name])
                    result.paths.extend(annotation.values("path", "value"))
                    result.produces.extend(annotation.values("produces"))
                    result.consumes.extend(annotation.values("consumes"))
                elif annotation.name == "RequestMapping":
                    result.paths.extend(annotation.values("path", "value"))
                    methods = annotation.values("method")
                    result.methods.extend(value.rsplit(".", 1)[-1].lower() for value in methods)
                    if not methods:
                        result.methods.extend(ALL_SPRING_METHODS)
                    result.produces.extend(annotation.values("produces"))
                    result.consumes.extend(annotation.values("consumes"))
            else:
                if annotation.name in JAX_METHODS:
                    result.methods.append(JAX_METHODS[annotation.name])
                elif annotation.name == "Path":
                    result.paths.extend(annotation.values("value"))
                elif annotation.name == "Produces":
                    result.produces.extend(annotation.values("value"))
                elif annotation.name == "Consumes":
                    result.consumes.extend(annotation.values("value"))
        return result

    def _application_paths(self) -> list[str]:
        if self.framework != "jaxrs":
            return [""]
        paths: list[str] = []
        for java_type in self.analysis.get_classes().values():
            for annotation in self._annotations(java_type.annotations):
                if annotation.name == "ApplicationPath":
                    paths.extend(annotation.values("value"))
        return paths or [""]

    def _resource_routes(
        self, qualified: str, visiting: set[str]
    ) -> list[tuple[str, list[tuple[Resource, Any, Mapping]]]]:
        if qualified in visiting:
            return []
        resource = self.resources[qualified]
        visiting = visiting | {qualified}
        parents: list[tuple[str, list[tuple[Resource, Any, Mapping]]]] = []
        if resource.framework == "jaxrs":
            for parent in self.resources.values():
                for locator, mapping in parent.locators:
                    returned = self.schemas._resolve_class(parse_java_type(locator.return_type).base)
                    if returned != qualified:
                        continue
                    for parent_prefix, chain in self._resource_routes(parent.qualified_name, visiting):
                        for locator_path in mapping.paths or [""]:
                            parents.append((
                                self._join_path("", parent_prefix, locator_path)[0],
                                chain + [(parent, locator, mapping)],
                            ))
        if parents:
            unique: dict[str, tuple[str, list[tuple[Resource, Any, Mapping]]]] = {}
            for route in parents:
                unique.setdefault(route[0], route)
            return list(unique.values())
        return [(path, []) for path in resource.paths or [""]]

    def _operation(
        self,
        resource: Resource,
        method: Any,
        mapping: Mapping,
        path: str,
        path_regexes: dict[str, str],
        http_method: str,
        inherited_parameters: list[dict[str, Any]],
    ) -> dict[str, Any]:
        operation: dict[str, Any] = {
            "operationId": self._operation_id(resource.qualified_name, method, http_method),
            "parameters": [],
        }
        parameters, request_body = self._parameters(resource, method, mapping)
        parameters = inherited_parameters + parameters
        by_key = {(parameter["name"], parameter["in"]): parameter for parameter in parameters}
        for name in re.findall(r"\{([^}]+)\}", path):
            key = (name, "path")
            if key not in by_key:
                by_key[key] = {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
            by_key[key]["required"] = True
            if name in path_regexes:
                if by_key[key]["schema"].get("type") == "string":
                    by_key[key]["schema"]["pattern"] = path_regexes[name]
                else:
                    by_key[key]["x-path-regex"] = path_regexes[name]
        operation["parameters"] = list(by_key.values())
        if not operation["parameters"]:
            operation.pop("parameters")
        if request_body:
            operation["requestBody"] = request_body
        operation["responses"] = self._responses(resource, method, mapping)
        return operation

    def _parameters(self, resource: Resource, method: Any, mapping: Mapping) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        parameters: list[dict[str, Any]] = []
        body_schemas: list[tuple[str, dict[str, Any], bool]] = []
        form_properties: dict[str, Any] = {}
        for parameter in method.parameters:
            annotations = self._annotations(parameter.annotations)
            annotation_by_name = {annotation.name: annotation for annotation in annotations}
            locations = SPRING_PARAMETERS if resource.framework == "spring" else JAX_PARAMETERS
            matched = next((name for name in locations if name in annotation_by_name), None)
            if matched:
                annotation = annotation_by_name[matched]
                location = locations[matched]
                name = annotation.value("name", "value") or parameter.name or "parameter"
                schema = self.schemas.schema_for(parameter.type) or {"type": "object"}
                default = self._default_value(annotation_by_name, annotation)
                if default is not None:
                    schema["default"] = self._coerce_default(default, schema)
                if location == "form":
                    form_properties[name] = schema
                    continue
                required = location == "path"
                if resource.framework == "spring" and matched in {"RequestParam", "RequestHeader", "CookieValue", "PathVariable"}:
                    raw_required = annotation.value("required")
                    required = raw_required.lower() != "false" if raw_required else default is None
                    if location == "path":
                        required = True
                item = {"name": name, "in": location, "required": required, "schema": schema}
                parameters.append(item)
                continue

            if "RequestBody" in annotation_by_name:
                annotation = annotation_by_name["RequestBody"]
                required_value = annotation.value("required")
                body_schemas.append((parameter.name or "body", self.schemas.schema_for(parameter.type) or {"type": "object"}, required_value != "false"))
            elif "BeanParam" in annotation_by_name or "ModelAttribute" in annotation_by_name:
                parameters.extend(self._bean_parameters(parameter.type, resource.framework))
            elif any(name in annotation_by_name for name in {"Context", "Suspended", "RequestAttribute", "SessionAttribute"}):
                continue
            elif resource.framework == "jaxrs":
                body_schemas.append((parameter.name or "body", self.schemas.schema_for(parameter.type) or {"type": "object"}, True))
            elif self._is_simple_schema(self.schemas.schema_for(parameter.type)):
                parameters.append({
                    "name": parameter.name or "parameter", "in": "query", "required": False,
                    "schema": self.schemas.schema_for(parameter.type) or {"type": "string"},
                })
            else:
                parameters.extend(self._bean_parameters(parameter.type, resource.framework))

        if form_properties:
            body_schemas.append(("form", {"type": "object", "properties": form_properties}, False))
        if not body_schemas:
            return parameters, None
        if len(body_schemas) == 1:
            _, body_schema, required = body_schemas[0]
        else:
            body_schema = {"type": "object", "properties": {name: schema for name, schema, _ in body_schemas}}
            required = any(item[2] for item in body_schemas)
        media_types = self._media_types(
            mapping.consumes or resource.consumes or
            (["application/x-www-form-urlencoded"] if form_properties else ["application/json"])
        )
        return parameters, {
            "required": required,
            "content": {media: {"schema": body_schema} for media in media_types},
        }

    def _bean_parameters(self, raw_type: str, framework: str) -> list[dict[str, Any]]:
        qualified = self.schemas._resolve_class(raw_type)
        if not qualified:
            return []
        result: list[dict[str, Any]] = []
        for field in self.analysis.get_class(qualified).field_declarations or []:
            annotations = self._annotations(field.annotations)
            by_name = {annotation.name: annotation for annotation in annotations}
            locations = SPRING_PARAMETERS if framework == "spring" else JAX_PARAMETERS
            matched = next((name for name in locations if name in by_name), None)
            for variable in field.variables:
                if framework == "spring" and not matched:
                    result.append({"name": variable, "in": "query", "required": False, "schema": self.schemas.schema_for(field.type) or {"type": "object"}})
                elif matched and locations[matched] != "form":
                    annotation = by_name[matched]
                    location = locations[matched]
                    result.append({
                        "name": annotation.value("name", "value") or variable,
                        "in": location,
                        "required": location == "path",
                        "schema": self.schemas.schema_for(field.type) or {"type": "object"},
                    })
        return result

    @staticmethod
    def _default_value(by_name: dict[str, JavaAnnotation], primary: JavaAnnotation) -> str | None:
        if "DefaultValue" in by_name:
            return by_name["DefaultValue"].value("value")
        value = primary.value("defaultValue")
        if value and "ValueConstants.DEFAULT_NONE" not in value and "\ue000" not in value:
            return value
        return None

    @staticmethod
    def _coerce_default(value: str, schema: dict[str, Any]) -> Any:
        try:
            if schema.get("type") == "integer":
                return int(value)
            if schema.get("type") == "number":
                return float(value)
            if schema.get("type") == "boolean":
                return value.lower() == "true"
        except ValueError:
            pass
        return value

    @staticmethod
    def _is_simple_schema(schema: dict[str, Any] | None) -> bool:
        return bool(schema and schema.get("type") in {"string", "integer", "number", "boolean"})

    def _responses(self, resource: Resource, method: Any, mapping: Mapping) -> dict[str, Any]:
        statuses = self._response_statuses(method)
        schema = self._response_schema(method)
        media_types = self._media_types(mapping.produces or resource.produces or ["application/json"])
        responses: dict[str, Any] = {}
        for status in sorted(statuses):
            key = str(status)
            response: dict[str, Any] = {"description": STATUS_DESCRIPTIONS.get(key, "Response")}
            if schema is not None and 200 <= status < 300 and status not in {204, 205}:
                response["content"] = {media: {"schema": schema} for media in media_types}
            responses[key] = response
        return responses

    def _response_schema(self, method: Any) -> dict[str, Any] | None:
        response_type = self.schemas.response_entity_type(method.return_type)
        if response_type:
            return self.schemas.schema_for(response_type)
        candidates: list[dict[str, Any]] = []
        variables = {variable.name: variable.type for variable in method.variable_declarations or []}
        variables.update({parameter.name: parameter.type for parameter in method.parameters if parameter.name})
        for call_site in method.call_sites or []:
            if call_site.method_name not in {"entity", "ok", "body"} or not call_site.argument_expr:
                continue
            schema = self._expression_schema(call_site.argument_expr[0], variables)
            if schema and schema not in candidates:
                candidates.append(schema)
        if not candidates:
            for expression in re.findall(r"\.(?:entity|ok|body)\s*\(\s*([^,)]+)", method.code or ""):
                schema = self._expression_schema(expression, variables)
                if schema and schema not in candidates:
                    candidates.append(schema)
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            return {"oneOf": candidates}
        return None

    def _expression_schema(self, expression: str, variables: dict[str, str]) -> dict[str, Any] | None:
        text = expression.strip()
        new_type = re.match(r"new\s+([\w.$]+)(?:\s*<[^>]+>)?\s*\(", text)
        if new_type:
            return self.schemas.schema_for(new_type.group(1))
        if text in variables:
            return self.schemas.schema_for(variables[text])
        if text.startswith('"'):
            return {"type": "string"}
        if re.fullmatch(r"-?\d+", text):
            return {"type": "integer", "format": "int32"}
        if re.fullmatch(r"-?\d+\.\d+", text):
            return {"type": "number", "format": "double"}
        if text in {"true", "false"}:
            return {"type": "boolean"}
        return None

    @staticmethod
    def _media_types(values: Iterable[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            normalized = MEDIA_TYPE_CONSTANTS.get(value.rsplit(".", 1)[-1], value)
            if normalized not in result:
                result.append(normalized)
        return result

    def _response_statuses(self, method: Any) -> set[int]:
        statuses: set[int] = set()
        for annotation in self._annotations(method.annotations):
            if annotation.name != "ResponseStatus":
                continue
            value = annotation.value("code", "value")
            resolved = self._status_value(value)
            if resolved:
                statuses.add(resolved)
        code = method.code or ""
        for builder, status in BUILDER_STATUSES.items():
            if re.search(rf"\b(?:ResponseEntity|Response)\s*\.\s*{builder}\s*\(", code):
                statuses.add(status)
        for raw in re.findall(r"\b(?:ResponseEntity|Response)\s*\.\s*status\s*\(\s*([^,)]+)", code):
            resolved = self._status_value(raw.strip())
            if resolved:
                statuses.add(resolved)
        for raw in re.findall(r"\bnew\s+ResponseEntity\s*<[^>]*>?\s*\([^;]*?HttpStatus\.([A-Z_]+)", code, re.DOTALL):
            resolved = self._status_value(raw)
            if resolved:
                statuses.add(resolved)
        return statuses or {200}

    @staticmethod
    def _status_value(raw: str | None) -> int | None:
        if not raw:
            return None
        value = raw.strip()
        if value.isdigit():
            return int(value)
        name = value.rsplit(".", 1)[-1].replace(")", "").strip()
        return STATUS_ALIASES.get(name)

    def _annotations(self, raw_annotations: list[str] | None) -> list[JavaAnnotation]:
        resolved: list[JavaAnnotation] = []
        for annotation in parse_annotations(raw_annotations):
            attributes = {
                name: tuple(self._resolve_constant(value) for value in values)
                for name, values in annotation.attributes.items()
            }
            resolved.append(JavaAnnotation(annotation.name, attributes))
        return resolved

    def _build_constant_table(self) -> dict[str, str]:
        """Collect compile-time String constants using CLDK's Tree-sitter wrapper."""

        candidates: dict[str, set[str]] = {}
        source_override = getattr(self.analysis, "source_code", None)
        for compilation_unit in self.analysis.get_compilation_units():
            if source_override and not Path(compilation_unit.file_path).is_file():
                source = source_override
            else:
                path = Path(compilation_unit.file_path)
                if not path.is_file():
                    continue
                try:
                    source = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    source = path.read_text(encoding="latin-1")
            captures = self.analysis.treesitter_java.frame_query_and_capture_output(
                '(variable_declarator name: (identifier) value: (_) ) @declarator',
                source,
            )
            class_names = list(compilation_unit.type_declarations)
            for capture in captures:
                node = capture.node
                if not node.parent or node.parent.type != "field_declaration":
                    continue
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if not name_node or not value_node:
                    continue
                name = name_node.text.decode()
                expression = value_node.text.decode()
                keys = {name}
                owner = node.parent
                while owner and owner.type not in {
                    "class_declaration", "interface_declaration", "enum_declaration",
                    "record_declaration", "annotation_type_declaration",
                }:
                    owner = owner.parent
                owner_name_node = owner.child_by_field_name("name") if owner else None
                if owner_name_node:
                    owner_name = owner_name_node.text.decode()
                    keys.add(f"{owner_name}.{name}")
                    for qualified in class_names:
                        if qualified.endswith(f".{owner_name}") or qualified.endswith(f"${owner_name}"):
                            keys.add(f"{qualified}.{name}")
                for key in keys:
                    candidates.setdefault(key, set()).add(expression)

        raw = {key: next(iter(values)) for key, values in candidates.items() if len(values) == 1}
        resolved: dict[str, str] = {}

        def resolve_key(key: str, visiting: set[str]) -> str | None:
            if key in resolved:
                return resolved[key]
            if key in visiting or key not in raw:
                return None
            value = self._eval_string_expression(raw[key], lambda ref: resolve_key(ref, visiting | {key}))
            if value is not None:
                resolved[key] = value
            return value

        for key in raw:
            resolve_key(key, set())
        return resolved

    def _resolve_constant(self, value: str) -> str:
        return self._eval_string_expression(value, self.constants.get) or value

    @staticmethod
    def _eval_string_expression(expression: str, lookup: Any) -> str | None:
        text = expression.strip()
        while text.startswith("(") and text.endswith(")"):
            text = text[1:-1].strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
            try:
                value = ast.literal_eval(text)
                return value if isinstance(value, str) else None
            except (SyntaxError, ValueError):
                return None

        parts: list[str] = []
        start = depth = 0
        quote: str | None = None
        escaped = False
        for index, char in enumerate(text):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in {'"', "'"}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "+" and depth == 0:
                parts.append(text[start:index])
                start = index + 1
        if parts:
            parts.append(text[start:])
            evaluated = [OpenAPIGenerator._eval_string_expression(part, lookup) for part in parts]
            return "".join(evaluated) if all(value is not None for value in evaluated) else None
        return lookup(text)

    def _operation_id(self, qualified: str, method: Any, http_method: str) -> str:
        base = re.sub(
            r"\W+", "_",
            f"{qualified.rsplit('.', 1)[-1]}_{method.signature.split('(', 1)[0]}_{http_method}",
        ).strip("_")
        candidate = base
        index = 2
        while candidate in self._operation_ids:
            candidate = f"{base}_{index}"
            index += 1
        self._operation_ids.add(candidate)
        return candidate

    @staticmethod
    def _join_path(*parts: str) -> tuple[str, dict[str, str]]:
        joined = "/".join(part.strip("/") for part in parts if part and part.strip("/"))
        path = "/" + joined if joined else "/"
        regexes: dict[str, str] = {}

        def replace(match: re.Match[str]) -> str:
            content = match.group(1)
            if ":" in content:
                name, pattern = content.split(":", 1)
                regexes[name] = pattern
                return "{" + name + "}"
            return match.group(0)

        return re.sub(r"\{([^{}]+)\}", replace, path), regexes


def generate_openapi(
    project_path: str | Path,
    *,
    title: str | None = None,
    version: str = "0.0.0",
    analysis_json_path: str | Path | None = None,
    eager: bool = False,
) -> dict[str, Any]:
    return OpenAPIGenerator.from_project(
        project_path, title=title, version=version,
        analysis_json_path=analysis_json_path, eager=eager,
    ).generate()


def generate_openapi_from_source(
    source_code: str, *, title: str = "Generated API", version: str = "0.0.0"
) -> dict[str, Any]:
    return OpenAPIGenerator.from_source(source_code, title=title, version=version).generate()
