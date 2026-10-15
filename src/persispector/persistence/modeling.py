"""Build reviewable persistence models from deterministic declarations.

The source-specific models remain separate. ORM declarations describe logical
types and schema-generation intent, while DB schema declarations describe
physical relational objects. A relational ORM projection contains only
explicit physical names, so correlation never guesses a naming strategy.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

from sqlglot import exp

from persispector.annotations import JavaAnnotation, parse_annotation
from persispector.persistence.models import (
    ColumnPair,
    ConstraintFinding,
    EvidenceArtifact,
    ExtractedConstraint,
    DBSchemaModel,
    DBSchemaContext,
    ModelCorrelation,
    ModelElementRef,
    ModeledConstraint,
    ModeledDependency,
    NameMapping,
    OrmAssociation,
    OrmAttribute,
    OrmJoinColumn,
    OrmPersistenceModel,
    OrmType,
    PersistenceModelBundle,
    RelationalColumn,
    RelationalSchemaProjection,
    RelationalTable,
    SchemaOperation,
    SourceLocation,
)
from persispector.persistence.sql_parsing import ast_errors, parse_sql


_RELATIONSHIPS = {"ManyToOne", "OneToOne", "OneToMany", "ManyToMany"}


def stable_model_id(prefix: str, *parts: object) -> str:
    raw = "\0".join(str(part) for part in parts)
    return prefix + "-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def build_orm_type(artifact: EvidenceArtifact, java_type: Any) -> OrmType:
    """Build a logical ORM type without inventing physical names."""

    qualified = artifact.mapped_type or "<unknown>"
    type_annotations = [parse_annotation(raw) for raw in java_type.annotations or []]
    by_type_name = {annotation.name: annotation for annotation in type_annotations}
    table_annotation = by_type_name.get("Table")
    table_name = _qualified_table_name(table_annotation)
    entity_annotation = by_type_name.get("Entity")
    inheritance_annotation = by_type_name.get("Inheritance")
    discriminator_annotation = by_type_name.get("DiscriminatorColumn")
    discriminator_name = (
        _nonblank(discriminator_annotation.value("name"))
        if discriminator_annotation
        else None
    )
    logical_name = (
        _nonblank(entity_annotation.value("name"))
        if entity_annotation
        else qualified
    ) or qualified
    orm_type = OrmType(
        model_id=stable_model_id("ormt", artifact.artifact_id, qualified),
        qualified_name=qualified,
        declaration_kind=artifact.metadata.get("declaration_kind", "mapped"),
        table=NameMapping(
            logical_name=logical_name,
            physical_name=table_name,
            explicit=bool(table_name),
        ),
        parent_types=list(java_type.extends_list or []),
        inheritance_strategy=(
            _enum_tail(inheritance_annotation.value("strategy"))
            if inheritance_annotation
            else None
        ),
        discriminator_column=(
            NameMapping(
                logical_name="discriminator",
                physical_name=discriminator_name,
                explicit=bool(discriminator_name),
            )
            if discriminator_annotation
            else None
        ),
        evidence_ids=[artifact.artifact_id],
        sources=[artifact.source],
    )

    members: dict[str, tuple[str, list[str]]] = {}
    for field in java_type.field_declarations or []:
        annotation_names = {
            parse_annotation(raw).name for raw in field.annotations or []
        }
        if {"static", "transient"} & set(field.modifiers or []):
            continue
        if "Transient" in annotation_names:
            continue
        for variable in field.variables or []:
            members[variable] = (field.type, list(field.annotations or []))
    for component in java_type.record_components or []:
        if "Transient" in {
            parse_annotation(raw).name for raw in component.annotations or []
        }:
            continue
        members[component.name] = (
            component.type,
            list(component.annotations or []),
        )
    for callable_declaration in (java_type.callable_declarations or {}).values():
        if callable_declaration.is_constructor or not callable_declaration.annotations:
            continue
        member = _property_name(callable_declaration.declaration)
        if member:
            callable_annotations = list(callable_declaration.annotations)
            if "Transient" in {
                parse_annotation(raw).name for raw in callable_annotations
            }:
                members.pop(member, None)
                continue
            previous_type, previous_annotations = members.get(member, ("", []))
            members[member] = (
                callable_declaration.return_type or previous_type,
                [*previous_annotations, *callable_annotations],
            )

    for member, (java_member_type, raw_annotations) in members.items():
        if not member:
            continue
        annotations = [parse_annotation(raw) for raw in raw_annotations]
        by_name = {annotation.name: annotation for annotation in annotations}
        column_annotation = by_name.get("Column")
        join_columns = _join_columns(by_name)
        physical_column = (
            _nonblank(column_annotation.value("name"))
            if column_annotation
            else None
        )
        attribute = OrmAttribute(
            model_id=stable_model_id("orma", orm_type.model_id, member),
            name=member,
            java_type=java_member_type,
            mapping_kind=_attribute_mapping_kind(by_name),
            column=NameMapping(
                logical_name=member,
                physical_name=physical_column,
                explicit=bool(physical_column),
            ),
            sources=[artifact.source],
        )
        orm_type.attributes.append(attribute)
        if "Id" in by_name or "EmbeddedId" in by_name:
            orm_type.identifier_attribute_ids.append(attribute.model_id)

        relationship = next(
            (by_name[name] for name in _RELATIONSHIPS if name in by_name), None
        )
        if relationship:
            foreign_key = _foreign_key_annotation(by_name, join_columns)
            association = OrmAssociation(
                model_id=stable_model_id("ormr", orm_type.model_id, member),
                member=member,
                java_type=java_member_type,
                relationship=relationship.name,
                target_entity=_relationship_target(java_member_type),
                join_columns=[_orm_join_column(item) for item in join_columns],
                foreign_key_mode=_foreign_key_mode(foreign_key),
                foreign_key_definition=(
                    _nonblank(foreign_key.value("foreignKeyDefinition"))
                    if foreign_key
                    else None
                ),
                sources=[artifact.source],
            )
            orm_type.associations.append(association)
    return orm_type


def assemble_persistence_models(
    artifacts: list[EvidenceArtifact],
    constraints: list[ExtractedConstraint],
    orm_types: list[OrmType],
    *,
    max_context_chars: int = 48_000,
) -> PersistenceModelBundle:
    """Attach declarations to source models and build explicit correlations."""

    artifact_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    orm = OrmPersistenceModel(types=sorted(orm_types, key=lambda item: item.qualified_name))
    db_schema = _build_db_schema_model(artifacts, constraints)
    bundle = PersistenceModelBundle(orm=orm, db_schema=db_schema)

    for constraint in constraints:
        owner_ids = _constraint_owner_ids(bundle, constraint)
        constraint.model_element_ids = owner_ids
        wrapper = ModeledConstraint(
            constraint_id=stable_model_id(
                "con", constraint.model_dump_json(exclude={"model_element_ids"})
            ),
            owner_ids=owner_ids,
            declaration=constraint,
            sources=[
                artifact_by_id[evidence_id].source
                for evidence_id in constraint.evidence_ids
                if evidence_id in artifact_by_id
            ],
        )
        target = (
            bundle.db_schema.constraints
            if constraint.layer == "schema"
            else bundle.orm.constraints
        )
        target.append(wrapper)
        _attach_constraint_id(bundle, owner_ids, wrapper.constraint_id)

    _build_dependencies(bundle, artifact_by_id)
    bundle.orm_projection = _project_orm_relational(bundle.orm)
    bundle.db_schema_projection = RelationalSchemaProjection(
        layer="db-schema",
        tables=[table.model_copy(deep=True) for table in bundle.db_schema.tables],
    )
    bundle.correlations = _correlate_models(bundle)
    _attach_artifact_context(artifacts, bundle, max_context_chars)
    return bundle


def project_constraints(models: PersistenceModelBundle) -> list[ExtractedConstraint]:
    """Return the backwards-compatible flat view derived from model objects."""

    wrappers = [*models.orm.constraints, *models.db_schema.constraints]
    return [wrapper.declaration for wrapper in wrappers]


def attach_findings_to_models(
    models: PersistenceModelBundle,
    findings: Iterable[ConstraintFinding],
    artifacts: Iterable[EvidenceArtifact],
) -> PersistenceModelBundle:
    """Attach LLM findings to a report-local copy of prepared models."""

    result = models.model_copy(deep=True)
    artifact_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    existing = {
        wrapper.constraint_id
        for wrapper in [*result.orm.constraints, *result.db_schema.constraints]
    }
    for finding in findings:
        if finding.origin != "llm":
            continue
        declaration = ExtractedConstraint.model_validate(
            finding.model_dump(
                exclude={"finding_id", "sources", "origin"}
            )
        )
        owner_ids = list(declaration.model_element_ids)
        if not owner_ids:
            owner_ids = _constraint_owner_ids(result, declaration)
            declaration.model_element_ids = owner_ids
        constraint_id = stable_model_id("con", finding.finding_id)
        if constraint_id in existing:
            continue
        existing.add(constraint_id)
        wrapper = ModeledConstraint(
            constraint_id=constraint_id,
            owner_ids=owner_ids,
            declaration=declaration,
            sources=list(finding.sources),
        )
        target = (
            result.db_schema.constraints
            if declaration.layer == "schema"
            else result.orm.constraints
        )
        target.append(wrapper)
        _attach_constraint_id(result, owner_ids, constraint_id)
    _build_dependencies(result, artifact_by_id)
    return result


def _build_db_schema_model(
    artifacts: list[EvidenceArtifact], constraints: list[ExtractedConstraint]
) -> DBSchemaModel:
    model = DBSchemaModel()
    tables: dict[tuple[str, str], RelationalTable] = {}
    artifact_by_id = {artifact.artifact_id: artifact for artifact in artifacts}

    db_schema_artifacts = [
        artifact
        for artifact in artifacts
        if artifact.kind in {"sql-ddl", "liquibase-changeset"}
    ]
    contexts: dict[str, DBSchemaContext] = {}
    for artifact in db_schema_artifacts:
        context = _schema_context(artifact)
        existing = contexts.setdefault(context.context_id, context)
        _append_unique(existing.evidence_ids, artifact.artifact_id)
        _append_source(existing.sources, artifact.source)
    model.contexts = sorted(contexts.values(), key=lambda item: item.key)
    for artifact in db_schema_artifacts:
        context_id = artifact.metadata.get("db_schema_context_id")
        if artifact.kind == "sql-ddl":
            statements = _parse_sql(artifact)
            if not statements:
                model.operations.append(
                    SchemaOperation(
                        operation_id=stable_model_id("op", artifact.artifact_id),
                        kind="other",
                        schema_context_id=context_id,
                        sequence=None,
                        evidence_id=artifact.artifact_id,
                        source=artifact.source,
                    )
                )
            for statement_index, statement in enumerate(statements):
                table_name, column_defs, operation_kind = _sql_declaration(
                    statement,
                    reject_invalid_ast=(
                        artifact.metadata.get("sql_parse_mode") == "tolerant"
                    ),
                )
                if table_name:
                    table = _db_schema_table(tables, table_name, artifact)
                    for column_name, declared_type in column_defs:
                        _db_schema_column(
                            table, column_name, artifact, declared_type
                        )
                model.operations.append(
                    SchemaOperation(
                        operation_id=stable_model_id(
                            "op", artifact.artifact_id, statement_index
                        ),
                        kind=operation_kind,
                        target_table=table_name,
                        target_columns=[name for name, _ in column_defs],
                        schema_context_id=context_id,
                        sequence=None,
                        evidence_id=artifact.artifact_id,
                        source=artifact.source,
                    )
                )
        elif artifact.kind == "liquibase-changeset":
            artifact_constraints = [
                item
                for item in constraints
                if item.layer == "schema"
                and artifact.artifact_id in item.evidence_ids
            ]
            target_table = next(
                (item.subject.table for item in artifact_constraints if item.subject.table),
                None,
            )
            model.operations.append(
                SchemaOperation(
                    operation_id=stable_model_id("op", artifact.artifact_id),
                    kind="liquibase-change",
                    target_table=target_table,
                    target_columns=sorted(
                        {
                            column
                            for item in artifact_constraints
                            for column in item.subject.columns
                        }
                    ),
                    schema_context_id=context_id,
                    sequence=None,
                    evidence_id=artifact.artifact_id,
                    source=artifact.source,
                )
            )

    for constraint in constraints:
        if constraint.layer != "schema" or not constraint.subject.table:
            continue
        artifact = next(
            (
                artifact_by_id[evidence_id]
                for evidence_id in constraint.evidence_ids
                if evidence_id in artifact_by_id
            ),
            None,
        )
        if artifact is None:
            continue
        table = _db_schema_table(tables, constraint.subject.table, artifact)
        for column_name in constraint.subject.columns:
            column = _db_schema_column(table, column_name, artifact)
            if constraint.kind == "type" and not column.declared_type:
                column.declared_type = constraint.details.column_type
    model.tables = sorted(
        tables.values(),
        key=lambda item: (
            item.schema_context_id or "",
            item.name.physical_name or "",
        ),
    )
    return model


def _schema_context(artifact: EvidenceArtifact) -> DBSchemaContext:
    context_id = artifact.metadata.get("db_schema_context_id") or stable_model_id(
        "dbctx", "default"
    )
    module = artifact.metadata.get("db_schema_module", ".")
    variant = artifact.metadata.get("db_schema_variant", "default")
    key = artifact.metadata.get("db_schema_context_key", f"{module}|{variant}")
    return DBSchemaContext(
        context_id=context_id,
        key=key,
        label=artifact.metadata.get("db_schema_context_label", key),
        module=module,
        variant=variant,
    )


def _parse_sql(artifact: EvidenceArtifact) -> list[exp.Expression]:
    """Use the same generic-first dialect cascade as static extraction."""

    return parse_sql(
        artifact.content,
        source_path=artifact.source.file_path,
    ).statements


def _sql_declaration(
    statement: exp.Expression,
    *,
    reject_invalid_ast: bool = False,
) -> tuple[str | None, list[tuple[str, str | None]], str]:
    if isinstance(statement, exp.Create) and statement.kind == "TABLE":
        if not isinstance(statement.this, exp.Schema):
            return None, [], "other"
        table = _table_name(statement.this.this)
        columns = [
            (
                item.name,
                item.args["kind"].sql()
                if isinstance(item.args.get("kind"), exp.DataType)
                else None,
            )
            for item in statement.this.expressions
            if (
                isinstance(item, exp.ColumnDef)
                and item.name
                and (not reject_invalid_ast or not ast_errors(item))
            )
        ]
        return table, columns, "create-table"
    if isinstance(statement, exp.Create) and statement.kind == "INDEX":
        index = statement.this
        table = _table_name(index.args.get("table")) if isinstance(index, exp.Index) else None
        return table, [], "create-unique-index"
    if isinstance(statement, exp.Alter) and statement.kind == "TABLE":
        table = _table_name(statement.this)
        columns = [
            (
                action.name,
                action.args["kind"].sql()
                if isinstance(action.args.get("kind"), exp.DataType)
                else None,
            )
            for action in statement.args.get("actions") or []
            if (
                isinstance(action, exp.ColumnDef)
                and action.name
                and (not reject_invalid_ast or not ast_errors(action))
            )
        ]
        return table, columns, "add-column" if columns else "alter-table"
    return None, [], "other"


def _db_schema_table(
    tables: dict[tuple[str, str], RelationalTable],
    name: str,
    artifact: EvidenceArtifact,
) -> RelationalTable:
    context_id = artifact.metadata.get("db_schema_context_id") or stable_model_id(
        "dbctx", "default"
    )
    key = (context_id, name.lower())
    if key not in tables:
        tables[key] = RelationalTable(
            model_id=stable_model_id("dbt", context_id, name.lower()),
            schema_context_id=context_id,
            name=NameMapping(
                logical_name=name, physical_name=name, explicit=True
            ),
        )
    table = tables[key]
    _append_unique(table.evidence_ids, artifact.artifact_id)
    _append_source(table.sources, artifact.source)
    return table


def _db_schema_column(
    table: RelationalTable,
    name: str,
    artifact: EvidenceArtifact,
    declared_type: str | None = None,
) -> RelationalColumn:
    column = next(
        (
            item
            for item in table.columns
            if (item.name.physical_name or "").lower() == name.lower()
        ),
        None,
    )
    if column is None:
        column = RelationalColumn(
            model_id=stable_model_id("dbcol", table.model_id, name.lower()),
            name=NameMapping(
                logical_name=name, physical_name=name, explicit=True
            ),
        )
        table.columns.append(column)
        table.columns.sort(key=lambda item: item.name.physical_name or "")
    if declared_type and not column.declared_type:
        column.declared_type = declared_type
    _append_unique(column.evidence_ids, artifact.artifact_id)
    _append_source(column.sources, artifact.source)
    return column


def _constraint_owner_ids(
    bundle: PersistenceModelBundle, constraint: ExtractedConstraint
) -> list[str]:
    subject = constraint.subject
    owners: list[str] = []
    if constraint.layer == "schema" and subject.table:
        table = _find_table(
            bundle.db_schema.tables,
            subject.table,
            schema_context_id=subject.schema_context_id,
        )
        if table:
            owners.append(table.model_id)
            for name in subject.columns:
                column = _find_column(table, name)
                if column:
                    owners.append(column.model_id)
        return owners
    orm_type = _find_orm_type(bundle.orm.types, subject.entity)
    if not orm_type:
        return owners
    owners.append(orm_type.model_id)
    for member in subject.fields:
        association = next(
            (item for item in orm_type.associations if item.member == member), None
        )
        attribute = next(
            (item for item in orm_type.attributes if item.name == member), None
        )
        if association and constraint.layer == "orm":
            owners.append(association.model_id)
        elif attribute:
            owners.append(attribute.model_id)
    if subject.columns and not subject.fields:
        for column_name in subject.columns:
            attribute = next(
                (
                    item
                    for item in orm_type.attributes
                    if item.column.explicit
                    and (item.column.physical_name or "").lower()
                    == column_name.lower()
                ),
                None,
            )
            if attribute:
                owners.append(attribute.model_id)
    return list(dict.fromkeys(owners))


def _attach_constraint_id(
    bundle: PersistenceModelBundle, owner_ids: list[str], constraint_id: str
) -> None:
    for element in _all_elements(bundle):
        if element.model_id in owner_ids:
            _append_unique(element.constraint_ids, constraint_id)


def _build_dependencies(
    bundle: PersistenceModelBundle,
    artifact_by_id: dict[str, EvidenceArtifact],
) -> None:
    existing_orm = {item.dependency_id for item in bundle.orm.dependencies}
    existing_db_schema = {
        item.dependency_id for item in bundle.db_schema.dependencies
    }
    for orm_type in bundle.orm.types:
        for parent_name in orm_type.parent_types:
            target_type = _find_orm_type(bundle.orm.types, parent_name)
            dependency = ModeledDependency(
                dependency_id=stable_model_id(
                    "dep", orm_type.model_id, "inheritance", parent_name
                ),
                kind="inheritance",
                layer="orm",
                source=ModelElementRef(
                    model_id=orm_type.model_id,
                    kind="orm-type",
                    name=orm_type.qualified_name,
                ),
                target=ModelElementRef(
                    model_id=target_type.model_id if target_type else None,
                    kind="orm-type" if target_type else None,
                    name=parent_name,
                ),
                enforcement="orm-schema-intent",
                evidence_ids=list(orm_type.evidence_ids),
                sources=list(orm_type.sources),
            )
            if dependency.dependency_id not in existing_orm:
                existing_orm.add(dependency.dependency_id)
                bundle.orm.dependencies.append(dependency)
                _append_unique(
                    orm_type.dependency_ids, dependency.dependency_id
                )

        for attribute in orm_type.attributes:
            if attribute.mapping_kind not in {"embedded", "embedded-id"}:
                continue
            target_type = _find_orm_type(bundle.orm.types, attribute.java_type)
            dependency = ModeledDependency(
                dependency_id=stable_model_id(
                    "dep", attribute.model_id, "embedded"
                ),
                kind="embedded",
                layer="orm",
                source=ModelElementRef(
                    model_id=attribute.model_id,
                    kind="orm-attribute",
                    name=f"{orm_type.qualified_name}.{attribute.name}",
                ),
                target=ModelElementRef(
                    model_id=target_type.model_id if target_type else None,
                    kind="orm-type" if target_type else None,
                    name=attribute.java_type,
                ),
                enforcement="orm-schema-intent",
                evidence_ids=list(orm_type.evidence_ids),
                sources=list(attribute.sources),
            )
            if dependency.dependency_id not in existing_orm:
                existing_orm.add(dependency.dependency_id)
                bundle.orm.dependencies.append(dependency)
                _append_unique(
                    attribute.dependency_ids, dependency.dependency_id
                )
                _append_unique(
                    orm_type.dependency_ids, dependency.dependency_id
                )

        for association in orm_type.associations:
            target_type = _find_orm_type(bundle.orm.types, association.target_entity)
            dependency = ModeledDependency(
                dependency_id=stable_model_id("dep", association.model_id, "association"),
                kind="association",
                layer="orm",
                source=ModelElementRef(
                    model_id=association.model_id,
                    kind="orm-association",
                    name=f"{orm_type.qualified_name}.{association.member}",
                ),
                target=ModelElementRef(
                    model_id=target_type.model_id if target_type else None,
                    kind="orm-type" if target_type else None,
                    name=association.target_entity,
                ),
                column_pairs=[
                    ColumnPair(
                        source=item.name.physical_name,
                        target=(
                            item.referenced_column.physical_name
                            if item.referenced_column
                            else None
                        ),
                    )
                    for item in association.join_columns
                ],
                enforcement="orm-schema-intent",
                evidence_ids=list(orm_type.evidence_ids),
                sources=list(association.sources),
            )
            if dependency.dependency_id in existing_orm:
                continue
            existing_orm.add(dependency.dependency_id)
            bundle.orm.dependencies.append(dependency)
            association.dependency_ids.append(dependency.dependency_id)
            orm_type.dependency_ids.append(dependency.dependency_id)

    for wrapper in [*bundle.orm.constraints, *bundle.db_schema.constraints]:
        declaration = wrapper.declaration
        if declaration.kind != "foreign-key":
            continue
        source_id = wrapper.owner_ids[-1] if wrapper.owner_ids else None
        if declaration.layer == "schema":
            target_table = _find_table(
                bundle.db_schema.tables,
                declaration.details.referenced_table,
                schema_context_id=declaration.subject.schema_context_id,
            )
            target = ModelElementRef(
                model_id=target_table.model_id if target_table else None,
                kind="db-schema-table" if target_table else None,
                name=declaration.details.referenced_table,
            )
            source_kind = (
                "db-schema-column"
                if len(wrapper.owner_ids) > 1
                else "db-schema-table"
            )
        else:
            target_type = _find_orm_type(
                bundle.orm.types, declaration.details.referenced_entity
            )
            target = ModelElementRef(
                model_id=target_type.model_id if target_type else None,
                kind="orm-type" if target_type else None,
                name=declaration.details.referenced_entity,
            )
            source_kind = "orm-association" if len(wrapper.owner_ids) > 1 else "orm-type"
        source_name = declaration.subject.table or declaration.subject.entity
        source_members = declaration.subject.columns or declaration.subject.fields
        dependency = ModeledDependency(
            dependency_id=stable_model_id("dep", wrapper.constraint_id, "foreign-key"),
            kind="foreign-key",
            layer=declaration.layer,
            source=ModelElementRef(
                model_id=source_id, kind=source_kind, name=source_name
            ),
            target=target,
            column_pairs=[
                ColumnPair(source=source, target=target_column)
                for source, target_column in zip(
                    source_members,
                    declaration.details.referenced_columns
                    or declaration.details.referenced_fields,
                )
            ],
            enforcement=declaration.enforcement,
            evidence_ids=list(declaration.evidence_ids),
            sources=[
                artifact_by_id[evidence_id].source
                for evidence_id in declaration.evidence_ids
                if evidence_id in artifact_by_id
            ],
            constraint_ids=[wrapper.constraint_id],
        )
        target_dependencies = (
            bundle.db_schema.dependencies
            if declaration.layer == "schema"
            else bundle.orm.dependencies
        )
        existing_target = (
            existing_db_schema
            if declaration.layer == "schema"
            else existing_orm
        )
        if dependency.dependency_id in existing_target:
            continue
        existing_target.add(dependency.dependency_id)
        target_dependencies.append(dependency)
        for element in _all_elements(bundle):
            if element.model_id in wrapper.owner_ids:
                _append_unique(element.dependency_ids, dependency.dependency_id)


def _project_orm_relational(orm: OrmPersistenceModel) -> RelationalSchemaProjection:
    tables: list[RelationalTable] = []
    for orm_type in orm.types:
        if not orm_type.table.explicit or not orm_type.table.physical_name:
            continue
        table = RelationalTable(
            model_id=stable_model_id("ort", orm_type.model_id),
            source_model_id=orm_type.model_id,
            name=orm_type.table.model_copy(),
            constraint_ids=list(orm_type.constraint_ids),
            dependency_ids=list(orm_type.dependency_ids),
            evidence_ids=list(orm_type.evidence_ids),
            sources=list(orm_type.sources),
        )
        for attribute in orm_type.attributes:
            if not attribute.column.explicit or not attribute.column.physical_name:
                continue
            table.columns.append(
                RelationalColumn(
                    model_id=stable_model_id("orc", attribute.model_id),
                    source_model_id=attribute.model_id,
                    name=attribute.column.model_copy(),
                    constraint_ids=list(attribute.constraint_ids),
                    dependency_ids=list(attribute.dependency_ids),
                    evidence_ids=list(orm_type.evidence_ids),
                    sources=list(attribute.sources),
                )
            )
        for association in orm_type.associations:
            for index, join_column in enumerate(association.join_columns):
                if not join_column.name.explicit or not join_column.name.physical_name:
                    continue
                if _find_column(table, join_column.name.physical_name):
                    continue
                table.columns.append(
                    RelationalColumn(
                        model_id=stable_model_id(
                            "orc", association.model_id, index
                        ),
                        source_model_id=association.model_id,
                        name=join_column.name.model_copy(),
                        constraint_ids=list(association.constraint_ids),
                        dependency_ids=list(association.dependency_ids),
                        evidence_ids=list(orm_type.evidence_ids),
                        sources=list(association.sources),
                    )
                )
        table.columns.sort(key=lambda item: item.name.physical_name or "")
        tables.append(table)
    return RelationalSchemaProjection(
        layer="orm",
        tables=sorted(tables, key=lambda item: item.name.physical_name or ""),
    )


def _correlate_models(bundle: PersistenceModelBundle) -> list[ModelCorrelation]:
    result: list[ModelCorrelation] = []
    db_schema_tables: dict[str, list[RelationalTable]] = {}
    for table in bundle.db_schema.tables:
        db_schema_tables.setdefault(
            (table.name.physical_name or "").lower(), []
        ).append(table)
    for orm_table in bundle.orm_projection.tables:
        physical_name = orm_table.name.physical_name or ""
        matches = _prefer_contexts_for_sources(
            db_schema_tables.get(physical_name.lower(), []),
            orm_table.sources,
            bundle.db_schema,
        )
        if not matches:
            matches = [None]
        for db_schema_table in matches:
            status = "matched" if db_schema_table else "unresolved"
            context_id = (
                db_schema_table.schema_context_id if db_schema_table else None
            )
            context_label = _context_label(bundle.db_schema, context_id)
            result.append(
                ModelCorrelation(
                    correlation_id=stable_model_id(
                        "corr",
                        "table",
                        orm_table.source_model_id,
                        physical_name.lower(),
                        context_id or "unresolved",
                    ),
                    kind="table",
                    orm_element_id=orm_table.source_model_id or orm_table.model_id,
                    db_schema_element_id=(
                        db_schema_table.model_id if db_schema_table else None
                    ),
                    db_schema_context_id=context_id,
                    status=status,
                    reason=(
                        f"Explicit ORM table name matches the DB schema table in {context_label}."
                        if db_schema_table
                        else "No DB schema table with the explicit ORM name was declared."
                    ),
                )
            )
            if not db_schema_table:
                continue
            for orm_column in orm_table.columns:
                column_name = orm_column.name.physical_name or ""
                db_schema_column = _find_column(db_schema_table, column_name)
                result.append(
                    ModelCorrelation(
                        correlation_id=stable_model_id(
                            "corr",
                            "column",
                            orm_column.source_model_id,
                            column_name.lower(),
                            context_id,
                        ),
                        kind="column",
                        orm_element_id=orm_column.source_model_id or orm_column.model_id,
                        db_schema_element_id=(
                            db_schema_column.model_id if db_schema_column else None
                        ),
                        db_schema_context_id=context_id,
                        status="matched" if db_schema_column else "unresolved",
                        reason=(
                            f"Explicit ORM column name matches a DB schema column in {context_label}."
                            if db_schema_column
                            else f"No DB schema column with the explicit ORM name was declared in {context_label}."
                        ),
                    )
                )
    return sorted(result, key=lambda item: item.correlation_id)


def _context_label(model: DBSchemaModel, context_id: str | None) -> str:
    context = next(
        (item for item in model.contexts if item.context_id == context_id), None
    )
    return context.label if context else context_id or "the default schema context"


def _prefer_contexts_for_sources(
    tables: list[RelationalTable],
    sources: list[SourceLocation],
    model: DBSchemaModel,
) -> list[RelationalTable]:
    if not tables or not sources:
        return tables
    source_path = sources[0].file_path.replace("\\", "/").strip("/")
    contexts = {item.context_id: item for item in model.contexts}
    matches: list[tuple[int, RelationalTable]] = []
    for table in tables:
        context = contexts.get(table.schema_context_id)
        if context is None:
            continue
        if (
            context.module == "."
            or source_path == context.module
            or source_path.startswith(context.module.rstrip("/") + "/")
        ):
            specificity = 0 if context.module == "." else len(
                context.module.split("/")
            )
            matches.append((specificity, table))
    if not matches:
        return tables
    most_specific = max(item[0] for item in matches)
    return [table for specificity, table in matches if specificity == most_specific]


def _attach_artifact_context(
    artifacts: list[EvidenceArtifact],
    bundle: PersistenceModelBundle,
    max_context_chars: int,
) -> None:
    for artifact in artifacts:
        evidence_id = artifact.artifact_id
        orm_types = [
            item for item in bundle.orm.types if evidence_id in item.evidence_ids
        ]
        db_schema_tables = [
            item
            for item in bundle.db_schema.tables
            if evidence_id in item.evidence_ids
        ]
        constraints = [
            item
            for item in [*bundle.orm.constraints, *bundle.db_schema.constraints]
            if evidence_id in item.declaration.evidence_ids
        ]
        dependencies = [
            item
            for item in [*bundle.orm.dependencies, *bundle.db_schema.dependencies]
            if evidence_id in item.evidence_ids
        ]
        operations = [
            item
            for item in bundle.db_schema.operations
            if item.evidence_id == evidence_id
        ]
        valid_ids = sorted(
            {
                element.model_id
                for element in _elements_for_context(orm_types, db_schema_tables)
            }
        )
        context = {
            "valid_model_element_ids": valid_ids,
            "orm_types": [item.model_dump(mode="json") for item in orm_types],
            "db_schema_tables": [
                item.model_dump(mode="json") for item in db_schema_tables
            ],
            "operations": [item.model_dump(mode="json") for item in operations],
            "known_constraints": [
                item.model_dump(mode="json") for item in constraints
            ],
            "known_dependencies": [
                item.model_dump(mode="json") for item in dependencies
            ],
        }
        artifact.model_context = _bound_model_context(
            context,
            orm_types,
            db_schema_tables,
            constraints,
            dependencies,
            operations,
            max_context_chars,
        )


def _bound_model_context(
    context: dict[str, Any],
    orm_types: list[OrmType],
    db_schema_tables: list[RelationalTable],
    constraints: list[ModeledConstraint],
    dependencies: list[ModeledDependency],
    operations: list[SchemaOperation],
    max_chars: int,
) -> dict[str, Any]:
    if len(json.dumps(context, sort_keys=True)) <= max_chars:
        return context
    elements = [
        {
            "model_id": item.model_id,
            "kind": "orm-type",
            "name": item.qualified_name,
        }
        for item in orm_types
    ]
    elements.extend(
        {
            "model_id": item.model_id,
            "kind": "orm-attribute",
            "name": item.name,
        }
        for orm_type in orm_types
        for item in orm_type.attributes
    )
    elements.extend(
        {
            "model_id": item.model_id,
            "kind": "orm-association",
            "name": item.member,
        }
        for orm_type in orm_types
        for item in orm_type.associations
    )
    elements.extend(
        {
            "model_id": table.model_id,
            "kind": "db-schema-table",
            "name": table.name.physical_name,
        }
        for table in db_schema_tables
    )
    elements.extend(
        {
            "model_id": column.model_id,
            "kind": "db-schema-column",
            "name": column.name.physical_name,
        }
        for table in db_schema_tables
        for column in table.columns
    )
    compact: dict[str, Any] = {
        "context_truncated": True,
        "elements": elements,
        "known_constraints": [
            {
                "constraint_id": item.constraint_id,
                "owner_ids": item.owner_ids,
                "kind": item.declaration.kind,
                "predicate": item.declaration.predicate,
            }
            for item in constraints
        ],
        "known_dependencies": [
            {
                "dependency_id": item.dependency_id,
                "kind": item.kind,
                "source": item.source.model_dump(mode="json"),
                "target": item.target.model_dump(mode="json"),
            }
            for item in dependencies
        ],
        "operations": [item.model_dump(mode="json") for item in operations],
    }
    shrinkable = [
        compact["elements"],
        compact["known_constraints"],
        compact["known_dependencies"],
        compact["operations"],
    ]
    while len(json.dumps(compact, sort_keys=True)) > max_chars and any(shrinkable):
        largest = max(shrinkable, key=len)
        if largest:
            largest.pop()
        else:
            shrinkable.remove(largest)
    compact["valid_model_element_ids"] = [
        item["model_id"] for item in compact["elements"]
    ]
    return compact


def _elements_for_context(
    orm_types: list[OrmType], db_schema_tables: list[RelationalTable]
) -> Iterable[Any]:
    for orm_type in orm_types:
        yield orm_type
        yield from orm_type.attributes
        yield from orm_type.associations
    for table in db_schema_tables:
        yield table
        yield from table.columns


def _all_elements(bundle: PersistenceModelBundle) -> Iterable[Any]:
    yield from _elements_for_context(
        bundle.orm.types, bundle.db_schema.tables
    )


def _find_orm_type(types: list[OrmType], name: str | None) -> OrmType | None:
    if not name:
        return None
    normalized = name.lower()
    return next(
        (
            item
            for item in types
            if item.qualified_name.lower() == normalized
            or item.qualified_name.rsplit(".", 1)[-1].lower() == normalized
        ),
        None,
    )


def _find_table(
    tables: list[RelationalTable],
    name: str | None,
    *,
    schema_context_id: str | None = None,
) -> RelationalTable | None:
    if not name:
        return None
    matches = [
        item
        for item in tables
        if (item.name.physical_name or "").lower() == name.lower()
        and (
            schema_context_id is None
            or item.schema_context_id == schema_context_id
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _find_column(table: RelationalTable, name: str) -> RelationalColumn | None:
    return next(
        (
            item
            for item in table.columns
            if (item.name.physical_name or "").lower() == name.lower()
        ),
        None,
    )


def _table_name(expression: exp.Expression | None) -> str | None:
    if not isinstance(expression, exp.Table):
        return None
    return ".".join(part.name for part in expression.parts if part.name) or None


def _join_columns(by_name: dict[str, JavaAnnotation]) -> list[JavaAnnotation]:
    if "JoinColumn" in by_name:
        return [by_name["JoinColumn"]]
    if "JoinColumns" in by_name:
        return [
            parse_annotation(raw) for raw in by_name["JoinColumns"].values("value")
        ]
    return []


def _orm_join_column(annotation: JavaAnnotation) -> OrmJoinColumn:
    name = _nonblank(annotation.value("name"))
    referenced = _nonblank(annotation.value("referencedColumnName"))
    return OrmJoinColumn(
        name=NameMapping(
            logical_name=name, physical_name=name, explicit=bool(name)
        ),
        referenced_column=(
            NameMapping(
                logical_name=referenced,
                physical_name=referenced,
                explicit=True,
            )
            if referenced
            else None
        ),
        nullable=_bool(annotation.value("nullable")),
        unique=_bool(annotation.value("unique")),
    )


def _foreign_key_annotation(
    by_name: dict[str, JavaAnnotation], join_columns: list[JavaAnnotation]
) -> JavaAnnotation | None:
    container = by_name.get("JoinColumns")
    raw = container.value("foreignKey") if container else None
    if not raw:
        raw = next(
            (
                item.value("foreignKey")
                for item in join_columns
                if item.value("foreignKey")
            ),
            None,
        )
    return parse_annotation(raw) if raw else None


def _foreign_key_mode(annotation: JavaAnnotation | None) -> str:
    if not annotation:
        return "unspecified"
    value = annotation.value("value")
    if not value:
        return "constraint"
    tail = value.rsplit(".", 1)[-1].replace("ConstraintMode.", "").upper()
    return {
        "CONSTRAINT": "constraint",
        "NO_CONSTRAINT": "no-constraint",
        "PROVIDER_DEFAULT": "provider-default",
    }.get(tail, "unspecified")


def _relationship_target(java_type: str) -> str:
    text = java_type.strip()
    generic = re.search(r"<(.+)>", text)
    if generic:
        text = generic.group(1).split(",")[-1].strip()
    text = text.replace("? extends ", "").replace("? super ", "")
    return text.rsplit(".", 1)[-1].rstrip("[]")


def _property_name(declaration: str) -> str | None:
    match = re.search(r"\b(?:get|is)([A-Z][A-Za-z0-9_$]*)\s*\(", declaration)
    if not match:
        return None
    name = match.group(1)
    return name[:1].lower() + name[1:]


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def _attribute_mapping_kind(
    annotations: dict[str, JavaAnnotation],
) -> str:
    if "EmbeddedId" in annotations:
        return "embedded-id"
    if "Embedded" in annotations:
        return "embedded"
    if "ElementCollection" in annotations:
        return "element-collection"
    return "basic"


def _enum_tail(value: str | None) -> str | None:
    text = _nonblank(value)
    return text.rsplit(".", 1)[-1] if text else None


def _nonblank(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _qualified_table_name(annotation: JavaAnnotation | None) -> str | None:
    if not annotation:
        return None
    name = _nonblank(annotation.value("name"))
    if not name:
        return None
    parts = [
        _nonblank(annotation.value("catalog")),
        _nonblank(annotation.value("schema")),
        name,
    ]
    return ".".join(part for part in parts if part)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _append_source(values: list[SourceLocation], value: SourceLocation) -> None:
    if value not in values:
        values.append(value)
