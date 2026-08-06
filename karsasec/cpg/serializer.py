"""CPGSerializer supporting JSON, binary pickle, and compressed .cpg.gz serialization for CPG graphs."""

from __future__ import annotations

import gzip
import json
import pickle
from pathlib import Path
from typing import Any

from karsasec.cpg.models import CPGEdge, CPGGraph, CPGMetadata, CPGNode, EdgeType, NodeType


class CPGSerializer:
    """Serializes and deserializes CPGGraph instances in JSON, binary, and .cpg.gz formats."""

    def to_json(self, graph: CPGGraph, indent: int = 2) -> str:
        return graph.to_json(indent=indent)

    def save_json(self, graph: CPGGraph, path: Path) -> None:
        path.write_text(self.to_json(graph))

    def save_compressed(self, graph: CPGGraph, path: Path) -> None:
        """Saves compressed .cpg.gz file using gzip JSON."""
        data = self.to_json(graph).encode("utf-8")
        with gzip.open(path, "wb") as f:
            f.write(data)

    def load_compressed(self, path: Path) -> CPGGraph:
        """Loads compressed .cpg.gz file and reconstructs CPGGraph."""
        with gzip.open(path, "rb") as f:
            data = f.read().decode("utf-8")
        return self.from_json(data)

    def save_binary(self, graph: CPGGraph, path: Path) -> None:
        """Saves raw binary pickle file."""
        with open(path, "wb") as f:
            pickle.dump(graph.to_dict(), f)

    def load_binary(self, path: Path) -> CPGGraph:
        """Loads raw binary pickle file."""
        with open(path, "rb") as f:
            dict_data = pickle.load(f)
        return self.from_dict(dict_data)

    def from_json(self, json_str: str) -> CPGGraph:
        dict_data = json.loads(json_str)
        return self.from_dict(dict_data)

    def from_dict(self, dict_data: dict[str, Any]) -> CPGGraph:
        meta_dict = dict_data.get("metadata", {})
        metadata = CPGMetadata(
            schema_version=meta_dict.get("schema_version", 1),
            engine_version=meta_dict.get("engine_version", "1.0.0"),
            generated_at=meta_dict.get("generated_at", ""),
            project_name=meta_dict.get("project_name", ""),
            languages=meta_dict.get("languages", []),
            node_count=meta_dict.get("node_count", 0),
            edge_count=meta_dict.get("edge_count", 0),
            duration_seconds=meta_dict.get("duration_seconds", 0.0),
        )
        graph = CPGGraph(metadata=metadata)

        for n_dict in dict_data.get("nodes", []):
            node = CPGNode(
                id=n_dict["id"],
                node_type=NodeType(n_dict["node_type"]),
                label=n_dict["label"],
                file_path=n_dict.get("file_path", ""),
                line_number=n_dict.get("line_number", 1),
                column=n_dict.get("column", 0),
                language=n_dict.get("language", "Generic"),
                labels=tuple(n_dict.get("labels", [])),
                attributes=n_dict.get("attributes", {}),
            )
            graph.add_node(node)

        for e_dict in dict_data.get("edges", []):
            edge = CPGEdge(
                source_id=e_dict["source_id"],
                target_id=e_dict["target_id"],
                edge_type=EdgeType(e_dict["edge_type"]),
                metadata=e_dict.get("metadata", {}),
            )
            graph.add_edge(edge)

        return graph
