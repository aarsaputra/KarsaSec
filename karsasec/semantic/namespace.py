"""Namespace resolution and formatting helpers."""

from typing import List

class NamespaceResolver:
    """Helper class to resolve fully qualified namespaces and path resolution."""

    @staticmethod
    def join(parts: List[str]) -> str:
        """Joins namespace parts with standard dots (e.g. ['os', 'system'] -> 'os.system')."""
        return ".".join(filter(None, parts))

    @staticmethod
    def get_parent_namespace(fqn: str) -> str:
        """Gets parent namespace (e.g. 'os.system' -> 'os')."""
        if "." in fqn:
            return fqn.rsplit(".", 1)[0]
        return ""
