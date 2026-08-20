"""FrameworkPass module integrating Framework Semantic Layer into Analysis PassManager and ArtifactStore."""

from __future__ import annotations

import logging
from pathlib import Path

from karsasec.framework.detector import FrameworkDetector
from karsasec.framework.models import (
    FrameworkEdge,
    FrameworkGraph,
    FrameworkMetadata,
    FrameworkNode,
    FrameworkNodeType,
)
from karsasec.framework.registry import framework_registry
from karsasec.rules.enums import AnalysisCapability
from karsasec.runtime.artifact_store import ArtifactStore
from karsasec.runtime.pass_manager import AnalysisPass, PassDescriptor

logger = logging.getLogger("karsasec.analysis.framework.framework_pass")


class FrameworkPass(AnalysisPass):
    """AnalysisPass constructing FrameworkGraph, FrameworkRegistry, and FrameworkMetadata from input CPG/AST artifacts."""

    def __init__(self, target_path: Path | None = None) -> None:
        descriptor = PassDescriptor(
            name="FrameworkPass",
            inputs=["AST", "IR", "CPG"],
            outputs=["framework_graph", "framework_registry", "framework_metadata"],
            required_capabilities=[AnalysisCapability.AST, AnalysisCapability.SEMANTIC],
            time_budget_ms=1000.0,
            memory_budget_mb=100.0,
        )
        super().__init__(descriptor)
        self.target_path = target_path or Path(".")
        self.detector = FrameworkDetector()

    def run(self, store: ArtifactStore) -> bool:
        """Executes FrameworkPass: detects frameworks, builds FrameworkGraph, writes artifacts to store."""
        try:
            file_nodes = store.get("AST", list) or []
            det_results = self.detector.detect(self.target_path, file_nodes=file_nodes)

            graph = FrameworkGraph()
            entrypoints: list[str] = []
            config_files: list[str] = []

            for res in det_results:
                definition = framework_registry.lookup(res.framework)
                lang = definition.language if definition else "Generic"
                fw_version = res.version.raw_version

                # 1. FRAMEWORK node
                fw_node = FrameworkNode(
                    id=f"fw::{res.framework.value.lower()}",
                    node_type=FrameworkNodeType.FRAMEWORK,
                    name=definition.name if definition else res.framework.value,
                    language=lang,
                    version=fw_version,
                    labels=("framework", res.framework.value.lower()),
                    attributes={"confidence": res.confidence, "reason": res.reason},
                )
                graph.add_node(fw_node)

                # 2. ENTRYPOINT nodes
                eps = definition.default_entrypoints if definition else ("main.py", "index.js")
                for ep in eps:
                    ep_node_id = f"ep::{res.framework.value.lower()}::{ep}"
                    ep_node = FrameworkNode(
                        id=ep_node_id,
                        node_type=FrameworkNodeType.ENTRYPOINT,
                        name=ep,
                        language=lang,
                        version=fw_version,
                        attributes={"file_path": ep},
                    )
                    graph.add_node(ep_node)
                    graph.add_edge(
                        FrameworkEdge(source_id=fw_node.id, target_id=ep_node_id, edge_type="HAS_ENTRYPOINT")
                    )
                    entrypoints.append(ep)

                # 3. CONFIG nodes
                configs = definition.default_config_files if definition else (".env", "config.py")
                for cfg in configs:
                    cfg_node_id = f"cfg::{res.framework.value.lower()}::{cfg}"
                    cfg_node = FrameworkNode(
                        id=cfg_node_id,
                        node_type=FrameworkNodeType.CONFIG,
                        name=cfg,
                        language=lang,
                        version=fw_version,
                        attributes={"file_path": cfg},
                    )
                    graph.add_node(cfg_node)
                    graph.add_edge(FrameworkEdge(source_id=fw_node.id, target_id=cfg_node_id, edge_type="HAS_CONFIG"))
                    config_files.append(cfg)

                # 4. MODULE nodes from AST
                for fn in file_nodes:
                    if hasattr(fn, "file_path") and fn.file_path:
                        mod_name = str(fn.file_path)
                        mod_node_id = f"mod::{mod_name}"
                        if mod_node_id not in graph.nodes:
                            mod_node = FrameworkNode(
                                id=mod_node_id,
                                node_type=FrameworkNodeType.MODULE,
                                name=mod_name,
                                language=getattr(fn, "language", lang),
                                version="1.0.0",
                            )
                            graph.add_node(mod_node)
                            graph.add_edge(
                                FrameworkEdge(source_id=fw_node.id, target_id=mod_node_id, edge_type="CONTAINS")
                            )

            metadata = FrameworkMetadata(
                detected_frameworks=tuple(det_results),
                entrypoints=tuple(dict.fromkeys(entrypoints)),
                config_files=tuple(dict.fromkeys(config_files)),
                statistics={"node_count": len(graph.nodes), "edge_count": len(graph.edges)},
            )

            # Store in ArtifactStore
            store.put("framework_graph", graph)
            store.put("framework_registry", framework_registry)
            store.put("framework_metadata", metadata)

            logger.info(f"FrameworkPass successfully executed. Detected {len(det_results)} frameworks.")
            return True
        except Exception as err:
            logger.error(f"FrameworkPass failed: {err}")
            return False
