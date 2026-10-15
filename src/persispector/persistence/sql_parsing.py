"""Shared SQLGlot parsing policy for persistence declarations.

The generic grammar is always attempted first.  A MySQL retry is allowed only
when the generic parse fails (or degrades to an opaque ``Command``) and the
source contains concrete MySQL syntax.  This keeps ordinary SQL dialect-neutral
while still recovering a structural AST for MySQL/TiDB-compatible DDL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError


_MYSQL_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AUTO_INCREMENT", re.compile(r"\bAUTO_INCREMENT\b", re.IGNORECASE)),
    ("UNSIGNED", re.compile(r"\bUNSIGNED\b", re.IGNORECASE)),
    ("ENGINE option", re.compile(r"\bENGINE\s*=", re.IGNORECASE)),
    (
        "character-set option",
        re.compile(r"\b(?:DEFAULT\s+)?CHARSET\s*=", re.IGNORECASE),
    ),
    (
        "inline KEY declaration",
        re.compile(r"(?m)^\s*(?:UNIQUE\s+)?KEY\s+[`\"A-Za-z_$]", re.IGNORECASE),
    ),
    ("MySQL executable comment", re.compile(r"/\*!\d{5}")),
    ("MySQL compatibility mode", re.compile(r"\bSET\s+MODE\s+MYSQL\b", re.IGNORECASE)),
)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass
class SQLParseResult:
    """The selected AST plus enough metadata to explain the parser decision."""

    statements: list[exp.Expression] = field(default_factory=list)
    dialect: str | None = None
    mode: str = "strict"
    detection_reasons: list[str] = field(default_factory=list)
    generic_issue: str | None = None
    dialect_issue: str | None = None

    @property
    def parser_label(self) -> str:
        return self.dialect or "generic"

    @property
    def partial(self) -> bool:
        return self.mode == "tolerant"


def detect_mysql(text: str, source_path: str | None = None) -> list[str]:
    """Return explicit source-local reasons that make a MySQL retry safe."""

    reasons = [label for label, pattern in _MYSQL_MARKERS if pattern.search(text)]
    if source_path:
        filename = PurePosixPath(source_path.replace("\\", "/")).name.lower()
        if re.search(r"(?:^|[-_.])mysql(?:[-_.]|$)", filename):
            reasons.append("MySQL-qualified filename")
    return list(dict.fromkeys(reasons))


def parse_sql(
    text: str,
    *,
    source_path: str | None = None,
) -> SQLParseResult:
    """Parse generic SQL first, then retry detected MySQL syntax if necessary.

    SQLGlot sometimes reports unsupported grammar by returning ``Command``
    instead of raising.  Such a result is an opaque parse, not a usable DDL AST,
    and therefore triggers the same evidence-backed fallback as an exception.
    If strict MySQL parsing also fails, tolerant MySQL parsing preserves any
    valid subtrees; callers must residualize the parse issue and malformed AST
    nodes rather than treating them as deterministic facts.
    """

    generic_statements: list[exp.Expression] = []
    generic_issue: str | None = None
    try:
        generic_statements = _parse(text)
        if _contains_opaque_command(generic_statements):
            generic_issue = "generic SQLGlot parsing produced an opaque Command AST"
    except SqlglotError as error:
        generic_issue = f"generic SQLGlot parsing failed ({_error_text(error)})"

    if generic_issue is None:
        return SQLParseResult(statements=generic_statements)

    detection_reasons = detect_mysql(text, source_path)
    if not detection_reasons:
        return SQLParseResult(
            statements=generic_statements,
            mode="opaque" if generic_statements else "failed",
            generic_issue=generic_issue,
        )

    mysql_issue: str | None = None
    try:
        mysql_statements = _parse(text, dialect="mysql")
        if _contains_opaque_command(mysql_statements):
            mysql_issue = "strict MySQL SQLGlot parsing produced an opaque Command AST"
        else:
            return SQLParseResult(
                statements=mysql_statements,
                dialect="mysql",
                detection_reasons=detection_reasons,
                generic_issue=generic_issue,
            )
    except SqlglotError as error:
        mysql_issue = f"strict MySQL SQLGlot parsing failed ({_error_text(error)})"

    try:
        tolerant = _parse(
            text,
            dialect="mysql",
            error_level=sqlglot.ErrorLevel.IGNORE,
        )
    except SqlglotError:
        tolerant = []
    return SQLParseResult(
        statements=tolerant,
        dialect="mysql",
        mode="tolerant",
        detection_reasons=detection_reasons,
        generic_issue=generic_issue,
        dialect_issue=mysql_issue,
    )


def ast_errors(expression: exp.Expression) -> list[str]:
    """Collect SQLGlot validation errors attached anywhere below a node."""

    return [
        message
        for node in expression.walk()
        for message in node.error_messages()
    ]


def _parse(
    text: str,
    *,
    dialect: str | None = None,
    error_level: sqlglot.ErrorLevel = sqlglot.ErrorLevel.RAISE,
) -> list[exp.Expression]:
    return [
        statement
        for statement in sqlglot.parse(
            text,
            read=dialect,
            error_level=error_level,
        )
        if statement is not None
    ]


def _contains_opaque_command(statements: list[exp.Expression]) -> bool:
    return any(isinstance(statement, exp.Command) for statement in statements)


def _error_text(error: SqlglotError) -> str:
    """Keep terminal color sequences out of persisted evidence JSON."""

    return _ANSI_ESCAPE.sub("", str(error))
