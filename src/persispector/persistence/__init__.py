"""Evidence-grounded extraction of declared persistence constraints."""

from persispector.persistence.analysis import (
    ConstraintExtractionClient,
    OpenAICompatibleConstraintClient,
    PersistenceConstraintAnalyzer,
    analyze_persistence_project,
)
from persispector.persistence.access import (
    PersistenceAccessGraphBuilder,
    build_persistence_access_graph,
)
from persispector.persistence.endpoint_access import (
    EndpointPersistenceGraphBuilder,
    extend_access_graph_with_endpoints,
    match_endpoint_parameters,
    refresh_endpoint_parameter_matches,
    trace_all_endpoints,
    trace_endpoint_persistence,
)
from persispector.persistence.discovery import PersistenceEvidencePreparer
from persispector.persistence.codeql_flow import (
    CodeQLTaintAnalyzer,
    apply_codeql_taint_analysis,
    refresh_codeql_taint_links,
)
from persispector.persistence.modeling import (
    attach_findings_to_models,
    project_constraints,
)
from persispector.persistence.models import (
    PersistenceAccessEdge,
    PersistenceAccessGraph,
    PersistenceAccessNode,
    EndpointPersistenceTrace,
    EndpointParameter,
    EndpointParameterMatch,
    EndpointParameterTaintFlow,
    CodeQLTaintAnalysis,
    DBSchemaContext,
    PersistenceTaintSink,
    PersistenceModelBundle,
)
from persispector.persistence.render import render_persistence_markdown

__all__ = [
    "ConstraintExtractionClient",
    "OpenAICompatibleConstraintClient",
    "PersistenceConstraintAnalyzer",
    "PersistenceEvidencePreparer",
    "PersistenceAccessGraph",
    "PersistenceAccessGraphBuilder",
    "PersistenceAccessEdge",
    "PersistenceAccessNode",
    "EndpointPersistenceGraphBuilder",
    "EndpointParameter",
    "EndpointParameterMatch",
    "EndpointParameterTaintFlow",
    "CodeQLTaintAnalysis",
    "CodeQLTaintAnalyzer",
    "DBSchemaContext",
    "PersistenceTaintSink",
    "EndpointPersistenceTrace",
    "PersistenceModelBundle",
    "analyze_persistence_project",
    "apply_codeql_taint_analysis",
    "refresh_codeql_taint_links",
    "attach_findings_to_models",
    "build_persistence_access_graph",
    "extend_access_graph_with_endpoints",
    "match_endpoint_parameters",
    "refresh_endpoint_parameter_matches",
    "render_persistence_markdown",
    "project_constraints",
    "trace_all_endpoints",
    "trace_endpoint_persistence",
]
