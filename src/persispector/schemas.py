"""Java-to-OpenAPI schema conversion backed by CLDK's symbol table."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from hamster.code_analysis.common.java_analyzer import Reachability

from persispector.annotations import parse_annotations


@dataclass(frozen=True)
class JavaType:
    base: str
    arguments: tuple["JavaType", ...] = ()
    array_depth: int = 0


def parse_java_type(raw: str | None) -> JavaType:
    text = (raw or "void").strip()
    text = re.sub(r"^\?\s+(?:extends|super)\s+", "", text)
    array_depth = 0
    while text.endswith("[]"):
        array_depth += 1
        text = text[:-2].strip()
    generic = text.find("<")
    if generic < 0:
        return JavaType(text, array_depth=array_depth)
    base = text[:generic].strip()
    inner = text[generic + 1 : text.rfind(">")]
    arguments: list[JavaType] = []
    start = depth = 0
    for index, char in enumerate(inner):
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
        elif char == "," and depth == 0:
            arguments.append(parse_java_type(inner[start:index]))
            start = index + 1
    if inner[start:].strip():
        arguments.append(parse_java_type(inner[start:]))
    return JavaType(base, tuple(arguments), array_depth)


PRIMITIVES: dict[str, dict[str, Any]] = {
    "boolean": {"type": "boolean"},
    "java.lang.Boolean": {"type": "boolean"},
    "Boolean": {"type": "boolean"},
    "byte": {"type": "integer", "format": "int32"},
    "java.lang.Byte": {"type": "integer", "format": "int32"},
    "short": {"type": "integer", "format": "int32"},
    "java.lang.Short": {"type": "integer", "format": "int32"},
    "int": {"type": "integer", "format": "int32"},
    "java.lang.Integer": {"type": "integer", "format": "int32"},
    "Integer": {"type": "integer", "format": "int32"},
    "long": {"type": "integer", "format": "int64"},
    "java.lang.Long": {"type": "integer", "format": "int64"},
    "Long": {"type": "integer", "format": "int64"},
    "float": {"type": "number", "format": "float"},
    "java.lang.Float": {"type": "number", "format": "float"},
    "double": {"type": "number", "format": "double"},
    "java.lang.Double": {"type": "number", "format": "double"},
    "char": {"type": "string", "minLength": 1, "maxLength": 1},
    "java.lang.Character": {"type": "string", "minLength": 1, "maxLength": 1},
    "java.lang.String": {"type": "string"},
    "String": {"type": "string"},
    "java.math.BigDecimal": {"type": "number"},
    "java.math.BigInteger": {"type": "integer"},
    "java.util.UUID": {"type": "string", "format": "uuid"},
    "java.net.URI": {"type": "string", "format": "uri"},
    "java.net.URL": {"type": "string", "format": "uri"},
    "java.time.LocalDate": {"type": "string", "format": "date"},
    "java.time.LocalDateTime": {"type": "string", "format": "date-time"},
    "java.time.OffsetDateTime": {"type": "string", "format": "date-time"},
    "java.time.ZonedDateTime": {"type": "string", "format": "date-time"},
    "java.time.Instant": {"type": "string", "format": "date-time"},
    "java.util.Date": {"type": "string", "format": "date-time"},
}

COLLECTIONS = {
    "Collection", "Iterable", "List", "ArrayList", "LinkedList", "Set", "HashSet",
    "SortedSet", "TreeSet", "Stream", "Page", "Slice",
}
MAPS = {"Map", "HashMap", "TreeMap", "SortedMap", "LinkedHashMap"}
WRAPPERS = {"Optional", "ResponseEntity", "HttpEntity", "CompletionStage", "CompletableFuture", "Mono"}


class SchemaBuilder:
    def __init__(self, analysis: Any):
        self.analysis = analysis
        self.classes = analysis.get_classes()
        self.reachability = Reachability(analysis)
        self.components: dict[str, dict[str, Any]] = {}
        self._building: set[str] = set()
        self._component_names: dict[str, str] = {}

    @staticmethod
    def is_void(raw: str | None) -> bool:
        return parse_java_type(raw).base in {"void", "java.lang.Void", "Void"}

    def schema_for(self, raw: str | None) -> dict[str, Any] | None:
        parsed = parse_java_type(raw)
        if parsed.base in {"void", "java.lang.Void", "Void"}:
            return None
        return self._schema(parsed)

    def response_entity_type(self, raw: str | None) -> str | None:
        parsed = parse_java_type(raw)
        if parsed.base.rsplit(".", 1)[-1] in {"ResponseEntity", "HttpEntity"}:
            if not parsed.arguments or parsed.arguments[0].base == "?":
                return None
            return self._render(parsed.arguments[0])
        if parsed.base in {"javax.ws.rs.core.Response", "jakarta.ws.rs.core.Response", "Response"}:
            return None
        return raw

    def _schema(self, java_type: JavaType) -> dict[str, Any]:
        if java_type.array_depth:
            element = JavaType(java_type.base, java_type.arguments, java_type.array_depth - 1)
            return {"type": "array", "items": self._schema(element)}

        base = java_type.base
        simple = base.rsplit(".", 1)[-1]
        if base in PRIMITIVES:
            return dict(PRIMITIVES[base])
        if simple in PRIMITIVES:
            return dict(PRIMITIVES[simple])
        if simple in WRAPPERS and java_type.arguments:
            return self._schema(java_type.arguments[0])
        if simple in COLLECTIONS:
            item = java_type.arguments[0] if java_type.arguments else JavaType("java.lang.Object")
            return {"type": "array", "items": self._schema(item)}
        if simple in {"Flux"}:
            item = java_type.arguments[0] if java_type.arguments else JavaType("java.lang.Object")
            return {"type": "array", "items": self._schema(item)}
        if simple in MAPS:
            value = java_type.arguments[-1] if java_type.arguments else JavaType("java.lang.Object")
            return {"type": "object", "additionalProperties": self._schema(value)}
        if base in {"java.lang.Object", "Object", "?"}:
            return {"type": "object"}

        qualified = self._resolve_class(base)
        if qualified:
            component_name = self._component_name(qualified)
            self._ensure_component(qualified, component_name)
            return {"$ref": f"#/components/schemas/{component_name}"}
        return {"type": "object", "x-java-type": base}

    def _resolve_class(self, name: str) -> str | None:
        if name in self.classes:
            return name
        matches = [qualified for qualified in self.classes if qualified.rsplit(".", 1)[-1] == name]
        return matches[0] if len(matches) == 1 else None

    def _component_name(self, qualified: str) -> str:
        if qualified in self._component_names:
            return self._component_names[qualified]
        simple = qualified.rsplit(".", 1)[-1].replace("$", "_")
        same_name = [name for name in self.classes if name.rsplit(".", 1)[-1].replace("$", "_") == simple]
        component_name = simple if len(same_name) == 1 else qualified.replace(".", "_").replace("$", "_")
        self._component_names[qualified] = component_name
        return component_name

    def _ensure_component(self, qualified: str, component_name: str) -> None:
        if component_name in self.components or qualified in self._building:
            return
        self._building.add(qualified)
        java_class = self.classes[qualified]
        if java_class.is_enum_declaration:
            self.components[component_name] = {
                "type": "string",
                "enum": [constant.name for constant in java_class.enum_constants or []],
            }
            self._building.remove(qualified)
            return

        properties: dict[str, Any] = {}
        fields = list(java_class.field_declarations or [])
        try:
            for parent in self.reachability.get_all_supertypes(qualified):
                parent_class = self.classes.get(parent)
                if parent_class:
                    fields = list(parent_class.field_declarations or []) + fields
        except Exception:
            # External or partially resolved inheritance should not prevent a schema.
            pass
        for field in fields:
            if "static" in (field.modifiers or []):
                continue
            annotations = parse_annotations(field.annotations)
            if any(annotation.name in {"JsonIgnore", "Transient"} for annotation in annotations):
                continue
            json_name = None
            for annotation in annotations:
                if annotation.name == "JsonProperty":
                    json_name = annotation.value("value")
            for variable in field.variables:
                properties[json_name or variable] = self._schema(parse_java_type(field.type))
        for component in java_class.record_components or []:
            properties[component.name] = self._schema(parse_java_type(component.type))
        schema: dict[str, Any] = {"type": "object"}
        if properties:
            schema["properties"] = properties
        self.components[component_name] = schema
        self._building.remove(qualified)

    @staticmethod
    def _render(java_type: JavaType) -> str:
        suffix = "[]" * java_type.array_depth
        if not java_type.arguments:
            return java_type.base + suffix
        return f"{java_type.base}<{', '.join(SchemaBuilder._render(arg) for arg in java_type.arguments)}>" + suffix
