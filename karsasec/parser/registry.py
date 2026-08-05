"""Parser Registry module for dynamic plugin registration and dual lookup."""

from pathlib import Path
from typing import Dict, List, Optional, Union
from karsasec.core.plugin import ParserPlugin

class ParserRegistry:
    """Registry managing language parser plugins with dual lookup (by extension & language)."""

    def __init__(self) -> None:
        self._language_map: Dict[str, ParserPlugin] = {}
        self._extension_map: Dict[str, ParserPlugin] = {}

    def register(self, plugin: ParserPlugin, extensions: Optional[List[str]] = None) -> None:
        """Registers a ParserPlugin under its supported language and associated file extensions."""
        lang_key = plugin.supported_language.lower()
        self._language_map[lang_key] = plugin

        if extensions:
            for ext in extensions:
                ext_key = ext.lower() if ext.startswith(".") else f".{ext.lower()}"
                self._extension_map[ext_key] = plugin

    def get_parser_by_language(self, language_name: str) -> Optional[ParserPlugin]:
        """Retrieves parser plugin registered for a language name."""
        return self._language_map.get(language_name.lower())

    def get_parser_by_extension(self, extension: str) -> Optional[ParserPlugin]:
        """Retrieves parser plugin registered for a file extension."""
        ext_key = extension.lower() if extension.startswith(".") else f".{extension.lower()}"
        return self._extension_map.get(ext_key)

    def get_parser_for_file(self, file_path: Union[str, Path]) -> Optional[ParserPlugin]:
        """Retrieves parser plugin appropriate for a given file path based on suffix or known filename patterns."""
        path = Path(file_path)
        parser = self.get_parser_by_extension(path.suffix)
        if parser:
            return parser

        filename = path.name.lower()
        if filename in {"dockerfile", "containerfile"}:
            return self.get_parser_by_extension(".dockerfile") or self.get_parser_by_language("Dockerfile")

        return None

    def list_parsers(self) -> List[ParserPlugin]:
        """Lists all registered ParserPlugin instances."""
        return list(self._language_map.values())

# Global singleton parser registry
parser_registry = ParserRegistry()
