"""Deterministic extraction for persistence declarations with fixed semantics.

This module deliberately preserves expressions such as CHECK predicates as
text. It interprets declaration syntax, not application-specific meaning. Any
constraint-bearing construct it cannot parse is returned as residual evidence
for the LLM stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Iterable
from xml.etree import ElementTree

from sqlglot import exp
import yaml

from persispector.annotations import JavaAnnotation, parse_annotation
from persispector.persistence.models import (
    ConstraintDetails,
    ConstraintSubject,
    EvidenceArtifact,
    ExtractedConstraint,
)
from persispector.persistence.sql_parsing import ast_errors, parse_sql


RELATIONSHIPS = {"ManyToOne", "OneToOne", "OneToMany", "ManyToMany"}
STANDARD_VALIDATION = {
    "AssertFalse", "AssertTrue", "DecimalMax", "DecimalMin", "Digits",
    "Email", "Future", "FutureOrPresent", "Max", "Min", "Negative",
    "NegativeOrZero", "NotBlank", "NotEmpty", "NotNull", "Null", "Past",
    "PastOrPresent", "Pattern", "Positive", "PositiveOrZero", "Size", "Valid",
}
CONSTRAINT_WORD = re.compile(
    r"\b(?:PRIMARY\s+KEY|FOREIGN\s+KEY|REFERENCES|NOT\s+NULL|UNIQUE|CHECK\s*\(|"
    r"ADD\s+CONSTRAINT|CREATE\s+UNIQUE\s+INDEX|EXCLUDE\s+(?:USING\s+\w+\s*)?\()\b",
    re.IGNORECASE,
)


@dataclass
class StaticExtraction:
    constraints: list[ExtractedConstraint] = field(default_factory=list)
    residuals: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def llm_content(self) -> str | None:
        if not self.residuals:
            return None
        return "\n\n".join(self.residuals)


def extract_java_constraints(
    artifact: EvidenceArtifact,
    java_type: Any,
    custom_constraints: set[str],
) -> StaticExtraction:
    """Translate known JPA/Hibernate/Validation annotations to constraints."""

    result = StaticExtraction()
    entity = artifact.mapped_type or ""
    type_annotations = [parse_annotation(raw) for raw in java_type.annotations or []]
    table_annotation = _first(type_annotations, "Table")
    table = _nonblank(table_annotation.value("name")) if table_annotation else None

    for annotation in type_annotations:
        if annotation.name == "Table":
            for nested in annotation.values("uniqueConstraints"):
                unique = parse_annotation(nested)
                if unique.name != "UniqueConstraint":
                    result.residuals.append(f"Unresolved @Table unique constraint: {nested}")
                    continue
                columns = unique.values("columnNames", "value")
                if columns:
                    kind = "composite-unique" if len(columns) > 1 else "unique"
                    result.constraints.append(
                        _constraint(
                            artifact, "orm", kind,
                            _subject(entity, table, columns=columns),
                            f"Columns {', '.join(columns)} must be unique",
                        )
                    )
            _add_jpa_checks(
                result, artifact, _subject(entity, table), annotation
            )
        elif annotation.name == "Check":
            _add_java_check(result, artifact, entity, table, annotation)
        elif annotation.name == "Checks":
            for raw in annotation.values("value"):
                nested = parse_annotation(raw)
                if nested.name == "Check":
                    _add_java_check(result, artifact, entity, table, nested)
                else:
                    result.residuals.append(f"Unresolved Hibernate check: {raw}")
        elif annotation.name in {
            "AssociationOverride", "AssociationOverrides",
            "AttributeOverride", "AttributeOverrides",
        }:
            result.residuals.append(
                f"Mapped-type override requiring contextual interpretation: {annotation}"
            )
        elif annotation.name in custom_constraints:
            result.residuals.append(
                f"Custom type-level validation annotation on {entity}: {annotation}"
            )

    for field_declaration in java_type.field_declarations or []:
        if {"static", "transient"} & set(field_declaration.modifiers or []):
            continue
        for variable in field_declaration.variables or []:
            _extract_java_member(
                result,
                artifact,
                entity,
                table,
                variable,
                field_declaration.type,
                field_declaration.annotations or [],
                custom_constraints,
            )

    for component in java_type.record_components or []:
        _extract_java_member(
            result,
            artifact,
            entity,
            table,
            component.name,
            component.type,
            component.annotations or [],
            custom_constraints,
        )

    for java_callable in (java_type.callable_declarations or {}).values():
        if java_callable.is_constructor or not java_callable.annotations:
            continue
        member = _property_name(java_callable.declaration)
        if not member:
            result.residuals.append(
                "Unresolved annotated persistence method: " + java_callable.declaration
            )
            continue
        _extract_java_member(
            result,
            artifact,
            entity,
            table,
            member,
            java_callable.return_type or "",
            java_callable.annotations,
            custom_constraints,
        )

    _combine_natural_ids(result, artifact, entity, table)
    return result


def _extract_java_member(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    entity: str,
    table: str | None,
    member: str,
    member_type: str,
    raw_annotations: list[str],
    custom_constraints: set[str],
) -> None:
    annotations = [parse_annotation(raw) for raw in raw_annotations]
    by_name = {annotation.name: annotation for annotation in annotations}
    if "Transient" in by_name:
        return
    column_annotation = by_name.get("Column")
    column = _nonblank(column_annotation.value("name")) if column_annotation else None
    subject = _subject(entity, table, fields=[member], columns=[column] if column else [])

    for annotation in annotations:
        if annotation.name in {
            "JoinTable", "CollectionTable", "AssociationOverride",
            "AssociationOverrides", "AttributeOverride", "AttributeOverrides",
        }:
            result.residuals.append(
                f"Mapped member {entity}.{member} requires contextual interpretation: "
                + next(raw for raw in raw_annotations if parse_annotation(raw).name == annotation.name)
            )

    if "Id" in by_name or "EmbeddedId" in by_name:
        result.constraints.append(
            _constraint(artifact, "orm", "primary-key", subject, f"{member} identifies the persistent row")
        )

    if column_annotation:
        nullable = _bool(column_annotation.value("nullable"))
        if nullable is False:
            result.constraints.append(
                _constraint(artifact, "orm", "not-null", subject, f"{member} must not be null")
            )
        if _bool(column_annotation.value("unique")) is True:
            result.constraints.append(
                _constraint(artifact, "orm", "unique", subject, f"{member} must be unique")
            )
        length = _int(column_annotation.value("length"))
        if length is not None:
            result.constraints.append(
                _constraint(
                    artifact, "orm", "length", subject,
                    f"{member} has declared column length {length}",
                    ConstraintDetails(length=length),
                )
            )
        precision = _int(column_annotation.value("precision"))
        scale = _int(column_annotation.value("scale"))
        if precision is not None or scale is not None:
            result.constraints.append(
                _constraint(
                    artifact, "orm", "precision-scale", subject,
                    f"{member} has declared precision/scale {precision}/{scale}",
                    ConstraintDetails(precision=precision, scale=scale),
                )
            )
        column_definition = column_annotation.value("columnDefinition")
        if column_definition:
            result.residuals.append(
                f"Mapped member {entity}.{member} has implementation-specific "
                f"columnDefinition: {column_definition}"
            )
        _add_jpa_checks(result, artifact, subject, column_annotation)

    basic = by_name.get("Basic")
    if basic and _bool(basic.value("optional")) is False:
        result.constraints.append(
            _constraint(artifact, "orm", "not-null", subject, f"{member} is not optional")
        )

    relationship = next((by_name[name] for name in RELATIONSHIPS if name in by_name), None)
    join_columns = _join_columns(by_name)
    if join_columns and not relationship:
        result.residuals.append(
            f"Join declaration on {entity}.{member} ({member_type}) has no recognized "
            f"relationship annotation: {' '.join(raw_annotations)}"
        )
    fk_subject: ConstraintSubject | None = None
    if relationship and join_columns and relationship.name in {"ManyToOne", "OneToOne"}:
        names = [item.value("name") for item in join_columns]
        explicit_names = [item for item in names if item]
        referenced = [
            value for item in join_columns
            if (value := item.value("referencedColumnName"))
        ]
        fk_subject = _subject(
            entity, table, fields=[member],
            columns=explicit_names if len(explicit_names) == len(join_columns) else [],
        )
        foreign_key = _foreign_key_annotation(by_name, join_columns)
        foreign_key_mode = _foreign_key_mode(foreign_key)
        if foreign_key_mode != "NO_CONSTRAINT":
            details = ConstraintDetails(
                referenced_entity=_base_type(member_type),
                referenced_columns=referenced,
            )
            if foreign_key_mode:
                details.custom["constraint_mode"] = foreign_key_mode
            if foreign_key and foreign_key.value("name"):
                details.custom["constraint_name"] = foreign_key.value("name") or ""
            result.constraints.append(
                _constraint(
                    artifact, "orm", "foreign-key", fk_subject,
                    f"{member} references {member_type}", details,
                )
            )
        if foreign_key and foreign_key.value("foreignKeyDefinition"):
            result.residuals.append(
                f"Dialect-specific foreignKeyDefinition on {entity}.{member}: "
                f"{foreign_key.value('foreignKeyDefinition')}"
            )
        if any(_bool(item.value("nullable")) is False for item in join_columns):
            result.constraints.append(
                _constraint(artifact, "orm", "not-null", fk_subject, f"{member} join column must not be null")
            )
        for join_column in join_columns:
            join_subject = _subject(
                entity,
                table,
                fields=[member],
                columns=[join_column.value("name")]
                if join_column.value("name")
                else [],
            )
            if _bool(join_column.value("unique")) is True:
                result.constraints.append(
                    _constraint(
                        artifact, "orm", "unique", join_subject,
                        f"{member} join column must be unique",
                    )
                )
            _add_jpa_checks(result, artifact, join_subject, join_column)
    elif relationship and join_columns:
        result.residuals.append(
            f"Relationship direction for {entity}.{member} ({member_type}) requires "
            f"contextual interpretation: {' '.join(raw_annotations)}"
        )
    if relationship and _bool(relationship.value("optional")) is False:
        result.constraints.append(
            _constraint(
                artifact, "orm", "not-null", fk_subject or subject,
                f"{member} relationship is required",
            )
        )

    if "NaturalId" in by_name:
        result.constraints.append(
            _constraint(
                artifact, "orm", "unique", subject,
                f"{member} is a natural identifier",
                ConstraintDetails(custom={"annotation": "NaturalId"}),
            )
        )
    for check in (
        annotation
        for annotation in annotations
        if annotation.name in {"Check", "Checks"}
    ):
        nested_checks = (
            [check] if check.name == "Check"
            else [parse_annotation(raw) for raw in check.values("value")]
        )
        for nested in nested_checks:
            predicate = nested.value("constraints", "value")
            if predicate:
                result.constraints.append(
                    _constraint(artifact, "orm", "check", subject, predicate)
                )
            else:
                result.residuals.append(f"Unresolved Hibernate member check: {nested}")
    on_delete = by_name.get("OnDelete")
    if on_delete:
        action = _enum_tail(on_delete.value("action", "value"))
        if action:
            result.constraints.append(
                _constraint(
                    artifact, "orm", "referential-action", fk_subject or subject,
                    f"Deletion uses {action}", ConstraintDetails(on_delete=action),
                )
            )

    for annotation in annotations:
        if annotation.name in STANDARD_VALIDATION:
            _extract_validation(result, artifact, subject, member, annotation)
        elif annotation.name in custom_constraints:
            result.residuals.append(
                f"Custom validation annotation on {entity}.{member}: "
                + next(raw for raw in raw_annotations if parse_annotation(raw).name == annotation.name)
            )


def _extract_validation(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    subject: ConstraintSubject,
    member: str,
    annotation: JavaAnnotation,
) -> None:
    name = annotation.name
    if name == "Valid":
        return
    if name == "NotNull":
        result.constraints.append(
            _constraint(artifact, "validation", "not-null", subject, f"{member} must not be null")
        )
        return
    if name in {"NotEmpty", "NotBlank", "Null", "AssertTrue", "AssertFalse"}:
        predicates = {
            "NotEmpty": f"{member} must not be null or empty",
            "NotBlank": f"{member} must contain non-whitespace text",
            "Null": f"{member} must be null",
            "AssertTrue": f"{member} must be true",
            "AssertFalse": f"{member} must be false",
        }
        result.constraints.append(
            _constraint(
                artifact, "validation", "custom", subject, predicates[name],
                ConstraintDetails(custom={"annotation": name}),
            )
        )
        return
    if name == "Size":
        minimum = _float(annotation.value("min"))
        maximum = _float(annotation.value("max"))
        if minimum is None and maximum is None:
            return
        result.constraints.append(
            _constraint(
                artifact, "validation", "range", subject,
                f"{member} size is between {minimum if minimum is not None else 0} "
                f"and {maximum if maximum is not None else 'the implementation maximum'}",
                ConstraintDetails(minimum=minimum if minimum is not None else 0, maximum=maximum),
            )
        )
        return
    if name in {"Min", "DecimalMin", "Max", "DecimalMax"}:
        value = _float(annotation.value("value"))
        if value is None:
            result.residuals.append(f"Unresolved @{name} value on {member}: {annotation}")
            return
        details = ConstraintDetails()
        if name in {"Min", "DecimalMin"}:
            details.minimum = value
        else:
            details.maximum = value
        if annotation.value("inclusive") is not None:
            details.custom["inclusive"] = annotation.value("inclusive") or ""
        result.constraints.append(
            _constraint(artifact, "validation", "range", subject, f"{member} satisfies @{name}({value})", details)
        )
        return
    if name in {"Positive", "PositiveOrZero", "Negative", "NegativeOrZero"}:
        bounds = {
            "Positive": (0.0, None, "false"),
            "PositiveOrZero": (0.0, None, "true"),
            "Negative": (None, 0.0, "false"),
            "NegativeOrZero": (None, 0.0, "true"),
        }
        minimum, maximum, inclusive = bounds[name]
        result.constraints.append(
            _constraint(
                artifact, "validation", "range", subject, f"{member} satisfies @{name}",
                ConstraintDetails(
                    minimum=minimum, maximum=maximum,
                    custom={"zero_inclusive": inclusive},
                ),
            )
        )
        return
    if name == "Digits":
        integer = _int(annotation.value("integer"))
        fraction = _int(annotation.value("fraction"))
        precision = integer + fraction if integer is not None and fraction is not None else None
        result.constraints.append(
            _constraint(
                artifact, "validation", "precision-scale", subject,
                f"{member} permits {integer} integer and {fraction} fractional digits",
                ConstraintDetails(
                    precision=precision, scale=fraction,
                    custom={"integer_digits": str(integer)} if integer is not None else {},
                ),
            )
        )
        return
    if name in {"Pattern", "Email"}:
        pattern = annotation.value("regexp", "value") if name == "Pattern" else "email"
        result.constraints.append(
            _constraint(
                artifact, "validation", "format-pattern", subject,
                f"{member} must match {pattern}", ConstraintDetails(pattern=pattern),
            )
        )
        return
    if name in {"Past", "PastOrPresent", "Future", "FutureOrPresent"}:
        result.constraints.append(
            _constraint(
                artifact, "validation", "custom", subject, f"{member} satisfies @{name}",
                ConstraintDetails(custom={"annotation": name}),
            )
        )


def extract_sql_constraints(artifact: EvidenceArtifact) -> StaticExtraction:
    return _extract_sql_text(artifact, artifact.content)


def _extract_sql_text(artifact: EvidenceArtifact, text: str) -> StaticExtraction:
    """Parse DDL into a SQLGlot AST and translate supported nodes.

    Generic SQL is always tried first. If it cannot produce a structural AST,
    explicit MySQL syntax permits a MySQL retry. A failed strict retry uses a
    tolerant MySQL AST, while preserving its parse error and invalid nodes as
    residual evidence rather than presenting them as deterministic facts.
    """

    result = StaticExtraction()
    parsed = parse_sql(text, source_path=artifact.source.file_path)
    result.metadata["sql_parser_dialect"] = parsed.parser_label
    result.metadata["sql_parse_mode"] = parsed.mode
    if parsed.detection_reasons:
        result.metadata["sql_dialect_evidence"] = "; ".join(
            parsed.detection_reasons
        )

    if not parsed.statements:
        result.residuals.append(
            f"Unsupported or dialect-specific SQL; {parsed.generic_issue or 'parsing failed'}:\n"
            + text.strip()
        )
        return result

    if parsed.partial:
        result.residuals.append(
            "The MySQL parser retained a partial AST after a strict parse "
            f"failure ({parsed.dialect_issue}). Analyze unclear portions of "
            "this declaration and do not repeat deterministic findings:\n"
            + text.strip()
        )

    for statement in parsed.statements:
        if not _extract_sql_statement(
            result,
            artifact,
            statement,
            reject_invalid_ast=parsed.partial,
        ):
            rendered = statement.sql(dialect=parsed.dialect)
            if CONSTRAINT_WORD.search(rendered) or isinstance(statement, exp.Command):
                result.residuals.append(
                    "Unsupported or dialect-specific SQL declaration:\n" + rendered
                )
    return result


def _extract_sql_statement(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    statement: exp.Expression,
    *,
    reject_invalid_ast: bool = False,
) -> bool:
    if isinstance(statement, exp.Create):
        if statement.kind == "TABLE" and isinstance(statement.this, exp.Schema):
            table = _sql_table_name(statement.this.this)
            if not table:
                return False
            for item in statement.this.expressions:
                if isinstance(item, exp.ColumnDef):
                    _extract_sql_column(
                        result,
                        artifact,
                        table,
                        item,
                        reject_invalid_ast=reject_invalid_ast,
                    )
                elif not _extract_sql_table_constraint(
                    result,
                    artifact,
                    table,
                    item,
                    reject_invalid_ast=reject_invalid_ast,
                ):
                    if CONSTRAINT_WORD.search(item.sql()):
                        result.residuals.append(f"In CREATE TABLE {table}: {item.sql()}")
            properties = statement.args.get("properties")
            if properties is not None and properties.expressions:
                result.residuals.append(
                    "Unsupported or dialect-specific CREATE TABLE properties:\n"
                    + properties.sql()
                )
            if statement.args.get("indexes"):
                result.residuals.append(
                    "Unsupported or dialect-specific inline indexes:\n"
                    + "\n".join(index.sql() for index in statement.args["indexes"])
                )
            return True
        if statement.kind == "INDEX" and statement.args.get("unique"):
            return _extract_unique_index(result, artifact, statement)
        return False

    if isinstance(statement, exp.Alter) and statement.kind == "TABLE":
        table = _sql_table_name(statement.this)
        if not table:
            return False
        for action in statement.args.get("actions") or []:
            if isinstance(action, exp.ColumnDef):
                _extract_sql_column(
                    result,
                    artifact,
                    table,
                    action,
                    reject_invalid_ast=reject_invalid_ast,
                )
            elif isinstance(action, exp.AlterColumn):
                if action.args.get("allow_null") is False:
                    column = _sql_name(action.this)
                    if column:
                        result.constraints.append(
                            _schema_constraint(
                                artifact, "not-null", table, [column],
                                f"{table}.{column} must not be null",
                            )
                        )
            elif isinstance(action, exp.AddConstraint):
                for constraint in action.expressions:
                    if not _extract_sql_table_constraint(
                        result,
                        artifact,
                        table,
                        constraint,
                        reject_invalid_ast=reject_invalid_ast,
                    ):
                        result.residuals.append(
                            f"In ALTER TABLE {table}: {constraint.sql()}"
                        )
            elif not _extract_sql_table_constraint(
                result,
                artifact,
                table,
                action,
                reject_invalid_ast=reject_invalid_ast,
            ):
                if CONSTRAINT_WORD.search(action.sql()):
                    result.residuals.append(f"In ALTER TABLE {table}: {action.sql()}")
        return True

    return False


def _extract_unique_index(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    statement: exp.Create,
) -> bool:
    index = statement.this
    if not isinstance(index, exp.Index):
        return False
    table = _sql_table_name(index.args.get("table"))
    parameters = index.args.get("params")
    if not table or parameters is None or parameters.args.get("where") is not None:
        return False
    columns: list[str] = []
    for expression in parameters.args.get("columns") or []:
        column = _sql_name(expression)
        if not column:
            return False
        columns.append(column)
    if not columns:
        return False
    kind = "composite-unique" if len(columns) > 1 else "unique"
    result.constraints.append(
        _schema_constraint(
            artifact, kind, table, columns,
            f"Columns {', '.join(columns)} must be unique",
        )
    )
    return True


def _extract_sql_column(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    table: str,
    definition: exp.ColumnDef,
    *,
    reject_invalid_ast: bool = False,
) -> None:
    errors = ast_errors(definition) if reject_invalid_ast else []
    if errors:
        result.residuals.append(
            f"Unclear column AST in CREATE/ALTER TABLE {table} "
            f"({'; '.join(errors)}): {definition.sql()}"
        )
        return
    column = _sql_name(definition.this)
    if not column:
        result.residuals.append(f"In CREATE/ALTER TABLE {table}: {definition.sql()}")
        return
    type_expression = definition.args.get("kind")
    if isinstance(type_expression, exp.DataType):
        if type_expression.this == exp.DataType.Type.USERDEFINED:
            result.residuals.append(
                f"Unsupported, user-defined, or dialect-specific SQL type on "
                f"{table}.{column}: {type_expression.sql()}"
            )
        else:
            type_text, base_type, length, precision, scale = _sql_data_type(
                type_expression
            )
            result.constraints.append(
                _schema_constraint(
                    artifact, "type", table, [column],
                    f"{table}.{column} has type {type_text}",
                    ConstraintDetails(column_type=base_type),
                )
            )
            if length is not None:
                result.constraints.append(
                    _schema_constraint(
                        artifact, "length", table, [column],
                        f"{table}.{column} has length {length}",
                        ConstraintDetails(length=length),
                    )
                )
            if precision is not None or scale is not None:
                result.constraints.append(
                    _schema_constraint(
                        artifact, "precision-scale", table, [column],
                        f"{table}.{column} has precision/scale {precision}/{scale}",
                        ConstraintDetails(precision=precision, scale=scale),
                    )
                )

    for constraint in definition.args.get("constraints") or []:
        kind = (
            constraint.args.get("kind")
            if isinstance(constraint, exp.ColumnConstraint)
            else constraint
        )
        if isinstance(kind, exp.NotNullColumnConstraint):
            if kind.args.get("allow_null") is not True:
                result.constraints.append(
                    _schema_constraint(
                        artifact, "not-null", table, [column],
                        f"{table}.{column} must not be null",
                    )
                )
        elif isinstance(kind, exp.PrimaryKeyColumnConstraint):
            result.constraints.append(
                _schema_constraint(
                    artifact, "primary-key", table, [column],
                    f"{table}.{column} identifies a row",
                )
            )
        elif isinstance(kind, exp.UniqueColumnConstraint):
            result.constraints.append(
                _schema_constraint(
                    artifact, "unique", table, [column],
                    f"{table}.{column} must be unique",
                )
            )
        elif isinstance(kind, exp.Reference):
            _add_sql_reference(result, artifact, table, [column], kind)
        elif isinstance(kind, exp.CheckColumnConstraint):
            _add_sql_check(result, artifact, table, [column], kind)
        elif kind is not None and type(kind).__name__ not in {
            "CollateColumnConstraint",
            "CommentColumnConstraint",
            "ComputedColumnConstraint",
            "DefaultColumnConstraint",
            "GeneratedAsIdentityColumnConstraint",
        }:
            result.residuals.append(
                f"Unsupported or dialect-specific clause on column "
                f"{table}.{column}: {constraint.sql()}"
            )


def _extract_sql_table_constraint(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    table: str,
    constraint: exp.Expression,
    *,
    reject_invalid_ast: bool = False,
) -> bool:
    errors = ast_errors(constraint) if reject_invalid_ast else []
    if errors:
        result.residuals.append(
            f"Unclear table-constraint AST in {table} "
            f"({'; '.join(errors)}): {constraint.sql()}"
        )
        return True
    if isinstance(constraint, exp.Constraint):
        handled = True
        for nested in constraint.expressions:
            handled = (
                _extract_sql_table_constraint(
                    result,
                    artifact,
                    table,
                    nested,
                    reject_invalid_ast=reject_invalid_ast,
                )
                and handled
            )
        return handled
    if isinstance(constraint, exp.PrimaryKey):
        columns = _sql_names(constraint.expressions)
        if not columns:
            return False
        result.constraints.append(
            _schema_constraint(
                artifact, "primary-key", table, columns,
                f"Columns {', '.join(columns)} identify a row",
            )
        )
        return True
    if isinstance(constraint, exp.UniqueColumnConstraint):
        schema = constraint.this
        columns = _sql_names(schema.expressions if isinstance(schema, exp.Schema) else [])
        if not columns:
            return False
        kind = "composite-unique" if len(columns) > 1 else "unique"
        result.constraints.append(
            _schema_constraint(
                artifact, kind, table, columns,
                f"Columns {', '.join(columns)} must be unique",
            )
        )
        return True
    if isinstance(constraint, exp.ForeignKey):
        columns = _sql_names(constraint.expressions)
        reference = constraint.args.get("reference")
        if not columns or not isinstance(reference, exp.Reference):
            return False
        return _add_sql_reference(result, artifact, table, columns, reference)
    if isinstance(constraint, exp.CheckColumnConstraint):
        _add_sql_check(result, artifact, table, [], constraint)
        return True
    return False


def _add_sql_check(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    table: str,
    columns: list[str],
    constraint: exp.CheckColumnConstraint,
) -> None:
    predicate = constraint.this.sql() if constraint.this is not None else constraint.sql()
    result.constraints.append(
        _schema_constraint(artifact, "check", table, columns, predicate)
    )


def _add_sql_reference(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    table: str,
    columns: list[str],
    reference: exp.Reference,
) -> bool:
    target_schema = reference.this
    if not isinstance(target_schema, exp.Schema):
        return False
    target = _sql_table_name(target_schema.this)
    target_columns = _sql_names(target_schema.expressions)
    if not target:
        return False
    result.constraints.append(
        _schema_constraint(
            artifact, "foreign-key", table, columns,
            f"Columns {', '.join(columns)} reference "
            f"{target}({', '.join(target_columns)})",
            ConstraintDetails(
                referenced_table=target, referenced_columns=target_columns
            ),
        )
    )
    on_delete, on_update = _sql_reference_actions(reference)
    if on_delete or on_update:
        result.constraints.append(
            _schema_constraint(
                artifact, "referential-action", table, columns,
                f"Reference actions are delete={on_delete}, update={on_update}",
                ConstraintDetails(on_delete=on_delete, on_update=on_update),
            )
        )
    return True


def _sql_reference_actions(reference: exp.Reference) -> tuple[str | None, str | None]:
    on_delete: str | None = None
    on_update: str | None = None
    for raw in reference.args.get("options") or []:
        option = _space_upper(str(raw))
        if option and option.startswith("ON DELETE "):
            on_delete = option.removeprefix("ON DELETE ")
        elif option and option.startswith("ON UPDATE "):
            on_update = option.removeprefix("ON UPDATE ")
    return on_delete, on_update


_SQL_LENGTH_TYPES = {
    "BINARY", "CHAR", "CHARACTER", "NCHAR", "NVARCHAR", "VARBINARY", "VARCHAR",
}
_SQL_PRECISION_TYPES = {"DEC", "DECIMAL", "FLOAT", "NUMBER", "NUMERIC"}


def _sql_data_type(
    data_type: exp.DataType,
) -> tuple[str, str, int | None, int | None, int | None]:
    type_text = data_type.sql()
    raw_type = data_type.this
    base_type = getattr(raw_type, "value", str(raw_type)).upper()
    parameters: list[int] = []
    for parameter in data_type.expressions:
        value = parameter.this if isinstance(parameter, exp.DataTypeParam) else parameter
        if not isinstance(value, exp.Literal) or value.is_string:
            continue
        parsed = _int(value.this)
        if parsed is not None:
            parameters.append(parsed)
    length = parameters[0] if parameters and base_type in _SQL_LENGTH_TYPES else None
    precision = parameters[0] if parameters and base_type in _SQL_PRECISION_TYPES else None
    scale = parameters[1] if len(parameters) > 1 and base_type in _SQL_PRECISION_TYPES else None
    return type_text, base_type, length, precision, scale


def _sql_table_name(expression: exp.Expression | None) -> str | None:
    if not isinstance(expression, exp.Table):
        return None
    parts = [_sql_name(part) for part in expression.parts]
    return ".".join(part for part in parts if part) or None


def _sql_names(expressions: Iterable[exp.Expression]) -> list[str]:
    names: list[str] = []
    for expression in expressions:
        name = _sql_name(expression)
        if not name:
            return []
        names.append(name)
    return names


def _sql_name(expression: exp.Expression | None) -> str | None:
    if isinstance(expression, exp.Ordered):
        expression = expression.this
    if isinstance(expression, exp.Column):
        return expression.name or None
    if isinstance(expression, exp.Identifier):
        return expression.name or None
    return None


def extract_liquibase_constraints(artifact: EvidenceArtifact) -> StaticExtraction:
    suffix = artifact.source.file_path.lower().rsplit(".", 1)[-1]
    if suffix == "xml":
        return _extract_liquibase_xml(artifact)
    try:
        data = json.loads(artifact.content) if suffix == "json" else yaml.safe_load(artifact.content)
    except (json.JSONDecodeError, yaml.YAMLError, TypeError, ValueError) as error:
        return StaticExtraction(residuals=[f"Unparsed Liquibase change set ({error}):\n{artifact.content}"])
    result = StaticExtraction()
    _walk_liquibase_data(result, artifact, data)
    return result


def _extract_liquibase_xml(artifact: EvidenceArtifact) -> StaticExtraction:
    result = StaticExtraction()
    try:
        root = ElementTree.fromstring(artifact.content)
    except ElementTree.ParseError as error:
        result.residuals.append(f"Unparsed Liquibase XML ({error}):\n{artifact.content}")
        return result
    for element in root.iter():
        name = element.tag.rsplit("}", 1)[-1]
        if name in {
            "changeSet", "preConditions", "validCheckSum", "rollback", "comment",
            "column", "constraints",
        }:
            continue
        if name in _LIQUIBASE_CHANGES:
            _handle_liquibase_change(result, artifact, name, _xml_change_data(element))
        elif _looks_constraint_bearing(name):
            result.residuals.append(ElementTree.tostring(element, encoding="unicode"))
    return result


def _walk_liquibase_data(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    value: Any,
) -> None:
    if isinstance(value, list):
        for item in value:
            _walk_liquibase_data(result, artifact, item)
        return
    if not isinstance(value, dict):
        return
    for name, child in value.items():
        if name in _LIQUIBASE_CHANGES:
            _handle_liquibase_change(result, artifact, name, child or {})
        elif _looks_constraint_bearing(name):
            result.residuals.append(json.dumps({name: child}, sort_keys=True))
        else:
            _walk_liquibase_data(result, artifact, child)


_LIQUIBASE_CHANGES = {
    "addPrimaryKey", "addForeignKeyConstraint", "addUniqueConstraint",
    "addNotNullConstraint", "addCheckConstraint", "createIndex", "createTable",
    "addColumn", "modifyDataType", "sql", "sqlFile", "customChange",
    "customChangeWrapper",
}


def _handle_liquibase_change(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    name: str,
    data: Any,
) -> None:
    if not isinstance(data, dict):
        result.residuals.append(f"Unparsed Liquibase {name}: {data}")
        return
    if name == "sql":
        sql = data.get("sql") or data.get("value") or data.get("text")
        if isinstance(sql, str):
            parsed = _extract_sql_text(artifact, sql)
            result.constraints.extend(parsed.constraints)
            result.residuals.extend(parsed.residuals)
        return
    if name in {"sqlFile", "customChange", "customChangeWrapper"}:
        result.residuals.append(f"Liquibase {name} requires external or custom interpretation: {data}")
        return
    if name in {"createTable", "addColumn"}:
        table = _liquibase_table_name(data)
        if not table:
            result.residuals.append(f"Liquibase {name} without tableName: {data}")
            return
        for column in _liquibase_columns(data):
            _extract_liquibase_column(result, artifact, table, column)
        return
    table = _liquibase_table_name(data, base=True)
    columns = _names(data.get("columnNames") or data.get("baseColumnNames") or data.get("columnName"))
    if name == "addPrimaryKey" and table and columns:
        result.constraints.append(
            _schema_constraint(artifact, "primary-key", table, columns, f"Columns {', '.join(columns)} identify a row")
        )
    elif name == "addUniqueConstraint" and table and columns:
        kind = "composite-unique" if len(columns) > 1 else "unique"
        result.constraints.append(
            _schema_constraint(artifact, kind, table, columns, f"Columns {', '.join(columns)} must be unique")
        )
    elif name == "addNotNullConstraint" and table and columns:
        for column in columns:
            result.constraints.append(
                _schema_constraint(artifact, "not-null", table, [column], f"{table}.{column} must not be null")
            )
    elif name == "addForeignKeyConstraint" and table and columns:
        target = _liquibase_table_name(data, referenced=True)
        target_columns = _names(data.get("referencedColumnNames"))
        result.constraints.append(
            _schema_constraint(
                artifact, "foreign-key", table, columns,
                f"Columns {', '.join(columns)} reference {target}({', '.join(target_columns)})",
                ConstraintDetails(referenced_table=target, referenced_columns=target_columns),
            )
        )
        on_delete = _space_upper(_nonblank(data.get("onDelete")))
        on_update = _space_upper(_nonblank(data.get("onUpdate")))
        if on_delete or on_update:
            result.constraints.append(
                _schema_constraint(
                    artifact, "referential-action", table, columns,
                    f"Reference actions are delete={on_delete}, update={on_update}",
                    ConstraintDetails(on_delete=on_delete, on_update=on_update),
                )
            )
    elif name == "addCheckConstraint" and table:
        predicate = _nonblank(data.get("constraintBody") or data.get("checkConstraint"))
        if predicate:
            result.constraints.append(_schema_constraint(artifact, "check", table, columns, predicate))
        else:
            result.residuals.append(f"Liquibase addCheckConstraint without body: {data}")
    elif name == "createIndex":
        if not columns:
            columns = [
                value for item in _liquibase_columns(data)
                if (value := _nonblank(item.get("name") or item.get("columnName")))
            ]
        if _bool(str(data.get("unique"))) is True and table and columns:
            kind = "composite-unique" if len(columns) > 1 else "unique"
            result.constraints.append(
                _schema_constraint(artifact, kind, table, columns, f"Columns {', '.join(columns)} must be unique")
            )
    elif name == "modifyDataType" and table and columns:
        new_type = _nonblank(data.get("newDataType"))
        if new_type:
            for column in columns:
                result.constraints.append(
                    _schema_constraint(
                        artifact, "type", table, [column], f"{table}.{column} has type {new_type}",
                        ConstraintDetails(column_type=_sql_type(new_type)[0]),
                    )
                )
    else:
        result.residuals.append(f"Unparsed Liquibase {name}: {data}")


def _liquibase_table_name(
    data: dict[str, Any], *, base: bool = False, referenced: bool = False
) -> str | None:
    """Preserve explicit Liquibase catalog/schema qualification."""

    if referenced:
        table = _nonblank(data.get("referencedTableName"))
        schema = _nonblank(data.get("referencedTableSchemaName"))
        catalog = _nonblank(data.get("referencedTableCatalogName"))
    elif base:
        table = _nonblank(data.get("tableName") or data.get("baseTableName"))
        schema = _nonblank(data.get("schemaName") or data.get("baseTableSchemaName"))
        catalog = _nonblank(data.get("catalogName") or data.get("baseTableCatalogName"))
    else:
        table = _nonblank(data.get("tableName"))
        schema = _nonblank(data.get("schemaName"))
        catalog = _nonblank(data.get("catalogName"))
    if not table:
        return None
    return ".".join(item for item in (catalog, schema, table) if item)


def _extract_liquibase_column(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    table: str,
    data: dict[str, Any],
) -> None:
    column = _nonblank(data.get("name") or data.get("columnName"))
    if not column:
        result.residuals.append(f"Liquibase column without name: {data}")
        return
    type_name = _nonblank(data.get("type"))
    if type_name:
        base, length, precision, scale = _sql_type(type_name)
        result.constraints.append(
            _schema_constraint(
                artifact, "type", table, [column], f"{table}.{column} has type {type_name}",
                ConstraintDetails(column_type=base),
            )
        )
        if length is not None:
            result.constraints.append(
                _schema_constraint(
                    artifact, "length", table, [column],
                    f"{table}.{column} has length {length}",
                    ConstraintDetails(length=length),
                )
            )
        if precision is not None or scale is not None:
            result.constraints.append(
                _schema_constraint(
                    artifact, "precision-scale", table, [column],
                    f"{table}.{column} has precision/scale {precision}/{scale}",
                    ConstraintDetails(precision=precision, scale=scale),
                )
            )
    constraints = data.get("constraints") or {}
    if not isinstance(constraints, dict):
        result.residuals.append(f"Unparsed Liquibase column constraints: {constraints}")
        return
    if _bool(str(constraints.get("nullable"))) is False:
        result.constraints.append(
            _schema_constraint(artifact, "not-null", table, [column], f"{table}.{column} must not be null")
        )
    if _bool(str(constraints.get("primaryKey"))) is True:
        result.constraints.append(
            _schema_constraint(artifact, "primary-key", table, [column], f"{table}.{column} identifies a row")
        )
    if _bool(str(constraints.get("unique"))) is True:
        result.constraints.append(
            _schema_constraint(artifact, "unique", table, [column], f"{table}.{column} must be unique")
        )
    references = _nonblank(constraints.get("references"))
    if references:
        match = re.match(r"(?is)^([^\s(]+)\s*\((.*?)\)$", references)
        if match:
            target = _identifier(match.group(1))
            target_columns = _column_list(match.group(2))
            result.constraints.append(
                _schema_constraint(
                    artifact, "foreign-key", table, [column],
                    f"{table}.{column} references {target}({', '.join(target_columns)})",
                    ConstraintDetails(referenced_table=target, referenced_columns=target_columns),
                )
            )
        else:
            result.residuals.append(f"Unparsed Liquibase reference: {references}")


def _xml_change_data(element: ElementTree.Element) -> dict[str, Any]:
    data: dict[str, Any] = dict(element.attrib)
    columns: list[dict[str, Any]] = []
    for child in element:
        name = child.tag.rsplit("}", 1)[-1]
        if name == "column":
            column = dict(child.attrib)
            constraint_element = next(
                (item for item in child if item.tag.rsplit("}", 1)[-1] == "constraints"),
                None,
            )
            if constraint_element is not None:
                column["constraints"] = dict(constraint_element.attrib)
            columns.append(column)
    if columns:
        data["columns"] = columns
        if element.tag.rsplit("}", 1)[-1] == "createIndex":
            data["columnNames"] = ",".join(item.get("name", "") for item in columns)
    if element.tag.rsplit("}", 1)[-1] == "sql":
        data["sql"] = element.text or ""
    return data


def _liquibase_columns(data: dict[str, Any]) -> Iterable[dict[str, Any]]:
    raw = data.get("columns") or data.get("column") or []
    if isinstance(raw, dict):
        raw = [raw]
    for item in raw:
        if isinstance(item, dict) and "column" in item and isinstance(item["column"], dict):
            yield item["column"]
        elif isinstance(item, dict):
            yield item


def _constraint(
    artifact: EvidenceArtifact,
    layer: str,
    kind: str,
    subject: ConstraintSubject,
    predicate: str,
    details: ConstraintDetails | None = None,
) -> ExtractedConstraint:
    enforcement = {
        "orm": "orm-schema-intent",
        "schema": "database",
        "validation": "application-validation",
    }[layer]
    return ExtractedConstraint(
        layer=layer,
        kind=kind,
        subject=subject,
        predicate=predicate,
        details=details or ConstraintDetails(),
        enforcement=enforcement,
        evidence_ids=[artifact.artifact_id],
        confidence=1.0,
    )


def _schema_constraint(
    artifact: EvidenceArtifact,
    kind: str,
    table: str,
    columns: list[str],
    predicate: str,
    details: ConstraintDetails | None = None,
) -> ExtractedConstraint:
    return _constraint(
        artifact, "schema", kind,
        ConstraintSubject(
            table=table, table_explicit=True,
            columns=columns, columns_explicit=bool(columns),
        ),
        predicate,
        details,
    )


def _subject(
    entity: str,
    table: str | None,
    *,
    fields: list[str] | None = None,
    columns: list[str] | None = None,
) -> ConstraintSubject:
    return ConstraintSubject(
        entity=entity,
        table=table,
        table_explicit=bool(table),
        fields=fields or [],
        columns=columns or [],
        columns_explicit=bool(columns),
    )


def _add_java_check(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    entity: str,
    table: str | None,
    annotation: JavaAnnotation,
) -> None:
    predicate = annotation.value("constraints", "value")
    if predicate:
        result.constraints.append(
            _constraint(artifact, "orm", "check", _subject(entity, table), predicate)
        )
    else:
        result.residuals.append(f"Unresolved Hibernate @Check: {annotation}")


def _join_columns(annotations: dict[str, JavaAnnotation]) -> list[JavaAnnotation]:
    if "JoinColumn" in annotations:
        return [annotations["JoinColumn"]]
    if "JoinColumns" in annotations:
        return [parse_annotation(raw) for raw in annotations["JoinColumns"].values("value")]
    return []


def _foreign_key_annotation(
    annotations: dict[str, JavaAnnotation],
    join_columns: list[JavaAnnotation],
) -> JavaAnnotation | None:
    container = annotations.get("JoinColumns")
    raw = container.value("foreignKey") if container else None
    if not raw:
        raw = next(
            (
                column.value("foreignKey")
                for column in join_columns
                if column.value("foreignKey")
            ),
            None,
        )
    return parse_annotation(raw) if raw else None


def _foreign_key_mode(annotation: JavaAnnotation | None) -> str | None:
    if not annotation:
        return None
    raw = annotation.value("value")
    # An explicitly written @ForeignKey with no value uses the annotation's
    # CONSTRAINT default. An omitted foreignKey element remains provider-owned.
    return _enum_tail(raw) if raw else "CONSTRAINT"


def _add_jpa_checks(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    subject: ConstraintSubject,
    owner: JavaAnnotation,
) -> None:
    for raw in owner.values("check"):
        check = parse_annotation(raw)
        if check.name != "CheckConstraint":
            result.residuals.append(f"Unresolved JPA check declaration: {raw}")
            continue
        predicate = check.value("constraint")
        if not predicate:
            result.residuals.append(f"JPA @CheckConstraint without constraint: {raw}")
            continue
        result.constraints.append(
            _constraint(artifact, "orm", "check", subject, predicate)
        )
        if check.value("options"):
            result.residuals.append(
                "Dialect-specific JPA @CheckConstraint options: "
                + (check.value("options") or "")
            )


def _combine_natural_ids(
    result: StaticExtraction,
    artifact: EvidenceArtifact,
    entity: str,
    table: str | None,
) -> None:
    declarations = [
        item
        for item in result.constraints
        if item.layer == "orm"
        and item.kind == "unique"
        and item.details.custom.get("annotation") == "NaturalId"
    ]
    if len(declarations) < 2:
        return
    fields = [field for item in declarations for field in item.subject.fields]
    columns = [column for item in declarations for column in item.subject.columns]
    all_columns_explicit = all(
        item.subject.columns_explicit and item.subject.columns
        for item in declarations
    )
    result.constraints = [
        item for item in result.constraints if item not in declarations
    ]
    result.constraints.append(
        _constraint(
            artifact,
            "orm",
            "composite-unique",
            _subject(
                entity,
                table,
                fields=fields,
                columns=columns if all_columns_explicit else [],
            ),
            f"Natural identifier members {', '.join(fields)} must be unique together",
            ConstraintDetails(custom={"annotation": "NaturalId"}),
        )
    )


def _first(annotations: list[JavaAnnotation], name: str) -> JavaAnnotation | None:
    return next((annotation for annotation in annotations if annotation.name == name), None)


def _property_name(declaration: str) -> str | None:
    match = re.search(r"\b(get|is)([A-Z][A-Za-z0-9_$]*)\s*\(", declaration)
    if not match:
        return None
    name = match.group(2)
    return name[:1].lower() + name[1:]


def _base_type(value: str) -> str:
    text = re.sub(r"<.*>", "", value).strip()
    return text.rsplit(".", 1)[-1]


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _float(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _nonblank(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _enum_tail(value: str | None) -> str | None:
    if not value:
        return None
    return value.rsplit(".", 1)[-1].upper()


def _space_upper(value: str | None) -> str | None:
    return re.sub(r"\s+", " ", value.strip()).upper() if value else None


def _names(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_identifier(str(item)) for item in value if str(item).strip()]
    return [_identifier(item) for item in _split_top_level(str(value))]


def _column_list(value: str) -> list[str]:
    return [_identifier(item) for item in _split_top_level(value)]


def _identifier(value: str) -> str:
    text = value.strip()
    parts = []
    for part in re.split(r"\s*\.\s*", text):
        if len(part) >= 2 and (
            (part[0], part[-1]) in {('"', '"'), ('`', '`'), ('[', ']')}
        ):
            part = part[1:-1]
        parts.append(part)
    return ".".join(parts)


def _sql_type(value: str) -> tuple[str, int | None, int | None, int | None]:
    text = re.sub(r"\s+", " ", value.strip())
    match = re.match(r"(?is)^(.+?)\s*\(\s*(\d+)\s*(?:,\s*(\d+)\s*)?\)$", text)
    if not match:
        return text.upper(), None, None, None
    base = match.group(1).strip().upper()
    first = int(match.group(2))
    second = int(match.group(3)) if match.group(3) is not None else None
    if second is not None or base in {"DECIMAL", "NUMERIC", "NUMBER"}:
        return base, None, first, second
    return base, first, None, None


def _split_top_level(value: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(value):
        char = value[index]
        if quote:
            if char == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif char in {'"', "'", '`'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
        index += 1
    tail = value[start:].strip()
    if tail:
        result.append(tail)
    return result


def _looks_constraint_bearing(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in ("constraint", "primarykey", "foreignkey", "unique", "notnull", "check"))
