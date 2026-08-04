"""ReportTarget streamable output targets preventing memory bloat on large scans."""

import io
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TextIO

class ReportTarget(ABC):
    """Abstract base target for streaming security report outputs."""

    @abstractmethod
    def write(self, content: str) -> None:
        """Writes content chunk to the target."""
        pass

    def close(self) -> None:
        """Flushes and closes target if applicable."""
        pass

class StringTarget(ReportTarget):
    """Buffers report content in memory for direct string retrieval."""

    def __init__(self) -> None:
        self._buffer = io.StringIO()

    def write(self, content: str) -> None:
        self._buffer.write(content)

    def get_content(self) -> str:
        return self._buffer.getvalue()

    def close(self) -> None:
        """No-op for string buffer target so get_content() remains accessible."""
        pass

class FileTarget(ReportTarget):
    """Streams report content directly into a filesystem file."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._file: TextIO = open(self.file_path, "w", encoding="utf-8")

    def write(self, content: str) -> None:
        self._file.write(content)

    def close(self) -> None:
        if not self._file.closed:
            self._file.flush()
            self._file.close()

class StreamTarget(ReportTarget):
    """Streams report content directly to a TextIO stream (e.g. sys.stdout)."""

    def __init__(self, stream: TextIO = sys.stdout) -> None:
        self.stream = stream

    def write(self, content: str) -> None:
        self.stream.write(content)
        self.stream.flush()
