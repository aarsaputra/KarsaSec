"""FrameworkGraphBuilder for converting ISR into FrameworkSemanticGraph."""

from __future__ import annotations

import logging

from karsasec.framework.builder_context import BuilderContext
from karsasec.framework.factories import FrameworkEdgeFactory, FrameworkNodeFactory
from karsasec.framework.intermediate import IntermediateSemanticRepresentation
from karsasec.framework.semantic_models import (
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
    SemanticEdgeType,
)
from karsasec.framework.symbol_table import SymbolBinding

logger = logging.getLogger("karsasec.framework.builder")


class GraphFrozenError(Exception):
    """Exception raised when attempting to mutate a frozen FrameworkSemanticGraph."""

    def __init__(self, message: str = "Cannot mutate a frozen FrameworkSemanticGraph") -> None:
        super().__init__(message)


class FrameworkGraphBuilder:
    """Graph construction engine transforming ISR into FrameworkSemanticGraph."""

    def __init__(self, context: BuilderContext | None = None) -> None:
        self.context: BuilderContext = context or BuilderContext()
        self._graph: FrameworkSemanticGraph = FrameworkSemanticGraph(
            schema_version=self.context.options.schema_version,
            generator_version=self.context.options.generator_version,
            compatibility_version=self.context.options.compatibility_version,
        )
        self._frozen: bool = False

    @property
    def is_frozen(self) -> bool:
        """Returns True if the builder / graph is frozen and immutable."""
        return self._frozen

    def freeze(self) -> FrameworkSemanticGraph:
        """Freezes the builder and returns the final immutable FrameworkSemanticGraph."""
        self._frozen = True
        return self._graph

    def clone(self) -> FrameworkGraphBuilder:
        """Creates a new mutable clone of the FrameworkGraphBuilder instance."""
        cloned_context = BuilderContext(
            isr=self.context.isr,
            registry=self.context.registry,
            symbol_table=self.context.symbol_table,
            artifact_store=self.context.artifact_store,
            options=self.context.options,
        )
        builder = FrameworkGraphBuilder(context=cloned_context)
        builder._graph = FrameworkSemanticGraph(
            schema_version=self._graph.schema_version,
            generator_version=self._graph.generator_version,
            compatibility_version=self._graph.compatibility_version,
            nodes={n.id: n for n in self._graph.nodes()},
            edges=self._graph.edges(),
        )
        builder._frozen = False
        return builder

    def build(self, isr: IntermediateSemanticRepresentation | None = None) -> FrameworkSemanticGraph:
        """Transforms ISR into a fully populated FrameworkSemanticGraph."""
        if self._frozen:
            raise GraphFrozenError("Cannot build on a frozen builder")

        target_isr = isr if isr is not None else self.context.isr

        # 1. Construct Nodes
        route_nodes: list[FrameworkSemanticNode] = []
        handler_nodes: list[FrameworkSemanticNode] = []
        controller_nodes: list[FrameworkSemanticNode] = []
        mw_nodes: list[FrameworkSemanticNode] = []
        model_nodes: list[FrameworkSemanticNode] = []
        config_nodes: list[FrameworkSemanticNode] = []
        tmpl_nodes: list[FrameworkSemanticNode] = []
        auth_nodes: list[FrameworkSemanticNode] = []

        for r in target_isr.routes:
            node = FrameworkNodeFactory.create_route_node(r)
            route_nodes.append(node)
            self._graph = self._graph.add_node(node)
            self.context.registry.add(node.id, r)

        for c in target_isr.controllers:
            node = FrameworkNodeFactory.create_controller_node(c)
            controller_nodes.append(node)
            self._graph = self._graph.add_node(node)
            self.context.registry.add(node.id, c)

        for h in target_isr.handlers:
            node = FrameworkNodeFactory.create_handler_node(h)
            handler_nodes.append(node)
            self._graph = self._graph.add_node(node)
            self.context.registry.add(node.id, h)

        for mw in target_isr.middlewares:
            node = FrameworkNodeFactory.create_middleware_node(mw)
            mw_nodes.append(node)
            self._graph = self._graph.add_node(node)
            self.context.registry.add(node.id, mw)

        for m in target_isr.models:
            node = FrameworkNodeFactory.create_model_node(m)
            model_nodes.append(node)
            self._graph = self._graph.add_node(node)
            self.context.registry.add(node.id, m)

        for cfg in target_isr.configs:
            node = FrameworkNodeFactory.create_config_node(cfg)
            config_nodes.append(node)
            self._graph = self._graph.add_node(node)
            self.context.registry.add(node.id, cfg)

        for tmpl in target_isr.templates:
            node = FrameworkNodeFactory.create_template_node(tmpl)
            tmpl_nodes.append(node)
            self._graph = self._graph.add_node(node)
            self.context.registry.add(node.id, tmpl)

        for a in target_isr.auths:
            node = FrameworkNodeFactory.create_auth_node(a)
            auth_nodes.append(node)
            self._graph = self._graph.add_node(node)
            self.context.registry.add(node.id, a)

        # 2. Construct Relationships (Edges)
        # Route -> Handler (HANDLES)
        for r_node in route_nodes:
            h_name = r_node.attributes.get("handler")
            if h_name:
                for h_node in handler_nodes:
                    if h_node.name == h_name or h_node.attributes.get("function_name") == h_name:
                        edge = FrameworkEdgeFactory.create_edge(r_node.id, h_node.id, SemanticEdgeType.HANDLES)
                        self._graph = self._graph.add_edge(edge)

                        # Update Symbol Table binding
                        binding = SymbolBinding(
                            symbol_path=f"route:{r_node.attributes.get('path')} -> handler:{h_name}",
                            route_path=r_node.attributes.get("path"),
                            handler_name=h_name,
                            cpg_node_id=h_node.cpg_node_id or r_node.cpg_node_id,
                        )
                        self.context.symbol_table.add_binding(binding)

        # Controller -> Handler (DECLARES)
        for c_node in controller_nodes:
            c_handlers = c_node.attributes.get("handlers", [])
            for h_name in c_handlers:
                for h_node in handler_nodes:
                    if h_node.name == h_name:
                        edge = FrameworkEdgeFactory.create_edge(c_node.id, h_node.id, SemanticEdgeType.DECLARES)
                        self._graph = self._graph.add_edge(edge)

        # Middleware -> Route (PROTECTS)
        for mw_node in mw_nodes:
            target_routes = mw_node.attributes.get("target_routes", [])
            for tr in target_routes:
                for r_node in route_nodes:
                    if r_node.attributes.get("path") == tr:
                        edge = FrameworkEdgeFactory.create_edge(mw_node.id, r_node.id, SemanticEdgeType.PROTECTS)
                        self._graph = self._graph.add_edge(edge)

        # Auth -> Route (PROTECTS)
        for auth_node in auth_nodes:
            protected_routes = auth_node.attributes.get("protected_routes", [])
            for pr in protected_routes:
                for r_node in route_nodes:
                    if r_node.attributes.get("path") == pr or pr == "*":
                        edge = FrameworkEdgeFactory.create_edge(auth_node.id, r_node.id, SemanticEdgeType.PROTECTS)
                        self._graph = self._graph.add_edge(edge)

        # Auto-freeze if specified in options
        if self.context.options.auto_freeze:
            self._frozen = True

        return self._graph

    def rebuild(self, isr: IntermediateSemanticRepresentation) -> FrameworkSemanticGraph:
        """Clears graph state and rebuilds from new ISR."""
        self._frozen = False
        self._graph = FrameworkSemanticGraph(
            schema_version=self.context.options.schema_version,
            generator_version=self.context.options.generator_version,
            compatibility_version=self.context.options.compatibility_version,
        )
        return self.build(isr)

    def update(self, node: FrameworkSemanticNode) -> FrameworkSemanticGraph:
        """Updates or adds a node in the graph."""
        if self._frozen:
            raise GraphFrozenError("Cannot update a frozen FrameworkSemanticGraph")
        self._graph = self._graph.add_node(node)
        return self._graph

    def replace(self, node_id: str, new_node: FrameworkSemanticNode) -> FrameworkSemanticGraph:
        """Replaces an existing node by ID."""
        if self._frozen:
            raise GraphFrozenError("Cannot replace in a frozen FrameworkSemanticGraph")
        self._graph = self._graph.remove_node(node_id).add_node(new_node)
        return self._graph

    def remove(self, node_id: str) -> FrameworkSemanticGraph:
        """Removes a node and its attached edges from graph."""
        if self._frozen:
            raise GraphFrozenError("Cannot remove from a frozen FrameworkSemanticGraph")
        self._graph = self._graph.remove_node(node_id)
        return self._graph
