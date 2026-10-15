"""Small parser for the normalized Java annotations emitted by CLDK."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class JavaAnnotation:
    name: str
    attributes: dict[str, tuple[str, ...]]

    def values(self, *names: str) -> list[str]:
        for name in names:
            if name in self.attributes:
                return list(self.attributes[name])
        return []

    def value(self, *names: str) -> str | None:
        values = self.values(*names)
        return values[0] if values else None


def _split_top_level(value: str, delimiter: str = ",") -> list[str]:
    result: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    depths = {"(": 0, "{": 0, "[": 0}
    closing = {")": "(", "}": "{", "]": "["}

    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in depths:
            depths[char] += 1
        elif char in closing:
            depths[closing[char]] = max(0, depths[closing[char]] - 1)
        elif char == delimiter and not any(depths.values()):
            result.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        result.append(tail)
    return result


def _find_top_level_equals(value: str) -> int:
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        elif char == "=" and depth == 0:
            return index
    return -1


def _decode_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        try:
            return str(ast.literal_eval(value))
        except (SyntaxError, ValueError):
            return value[1:-1]
    return value


def _decode_value(value: str) -> tuple[str, ...]:
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        return tuple(_decode_scalar(item) for item in _split_top_level(value[1:-1]))
    return (_decode_scalar(value),)


def parse_annotation(raw: str) -> JavaAnnotation:
    """Parse annotations such as ``@GetMapping(path={"/a", "/b"})``."""

    text = raw.strip()
    if text.startswith("@"):
        text = text[1:]
    open_paren = text.find("(")
    if open_paren < 0:
        return JavaAnnotation(text.rsplit(".", 1)[-1], {})

    name = text[:open_paren].strip().rsplit(".", 1)[-1]
    body = text[open_paren + 1 :]
    if body.endswith(")"):
        body = body[:-1]
    attributes: dict[str, tuple[str, ...]] = {}
    positional: list[str] = []
    for item in _split_top_level(body):
        equals = _find_top_level_equals(item)
        if equals < 0:
            positional.extend(_decode_value(item))
        else:
            key = item[:equals].strip()
            attributes[key] = _decode_value(item[equals + 1 :])
    if positional:
        attributes["value"] = tuple(positional)
    return JavaAnnotation(name, attributes)


def parse_annotations(raw_annotations: list[str] | None) -> list[JavaAnnotation]:
    return [parse_annotation(raw) for raw in raw_annotations or []]
