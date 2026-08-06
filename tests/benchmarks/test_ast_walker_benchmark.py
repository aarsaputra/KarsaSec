"""Informational performance benchmark measuring ASTWalker streaming throughput."""

import time
from pathlib import Path

from karsasec.parser.ast import ASTWalker
from karsasec.parser.tree_sitter import ts_engine


def test_benchmark_ast_walker_throughput(tmp_path: Path) -> None:
    """Informational benchmark recording ASTWalker nodes/sec traversal rate."""
    sample_code = b"""
import os
import sys

class Worker:
    def process(self, data):
        if not data:
            return None
        return os.system(data)

def main():
    w = Worker()
    w.process("ls")

if __name__ == '__main__':
    main()
"""
    file_path = tmp_path / "large_file.py"
    file_path.write_bytes(sample_code)

    root = ts_engine.parse_code(sample_code, "python", file_path=file_path)
    assert root is not None

    walker = ASTWalker()
    iterations = 500
    start_time = time.perf_counter()

    total_nodes_visited = 0
    for _ in range(iterations):
        for node in walker.walk(root):
            total_nodes_visited += 1

    elapsed = time.perf_counter() - start_time
    nodes_per_sec = total_nodes_visited / elapsed if elapsed > 0 else 0

    print(f"\n[ASTWalker Benchmark] Visited {total_nodes_visited} nodes in {elapsed:.4f}s ({nodes_per_sec:,.0f} nodes/sec)")
    assert total_nodes_visited > 0
