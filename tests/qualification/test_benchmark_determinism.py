"""Qualification test suite verifying 100-run SHA-256 fingerprint determinism and performance metrics."""

import hashlib
from pathlib import Path
from karsasec.cli.commands.scan import execute_scan_command
from karsasec.core.execution import RuleExecutor, ScanContext
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory

TEST_SNIPPET = b"""
import os
import sqlite3

def handle_request(user_input):
    os.system(user_input)
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = " + user_input)
"""


def test_100_run_scan_determinism():
    """Runs static analysis scan 100 times over identical code and verifies 100% fingerprint equality."""
    tmp_path = Path("/tmp/test_determinism_sample.py")
    tmp_path.write_bytes(TEST_SNIPPET)

    rules_dir = get_default_rules_directory()
    loader = YAMLRuleLoader()
    rules = loader.load_directory(rules_dir)

    parser = PythonParserPlugin()
    parse_res = parser.parse_file(tmp_path)

    executor = RuleExecutor()
    fingerprints_history = []

    for _ in range(100):
        scan_ctx = ScanContext(
            file_node=parse_res.root,
            source_bytes=TEST_SNIPPET,
            file_path=tmp_path,
            symbol_table=parse_res.symbol_table,
            language="Python",
        )
        res = executor.execute_scan(scan_ctx, rules)

        run_fingerprints = [f.fingerprint for f in res.findings]
        hasher = hashlib.sha256()
        for fp in sorted(run_fingerprints):
            hasher.update(fp.encode("utf-8"))

        fingerprints_history.append((len(res.findings), hasher.hexdigest()))

    first_len, first_hash = fingerprints_history[0]
    for idx, (flen, fhash) in enumerate(fingerprints_history[1:], start=2):
        assert flen == first_len, f"Run {idx} finding count mismatch: expected {first_len}, got {flen}"
        assert fhash == first_hash, f"Run {idx} SHA-256 fingerprint hash mismatch: expected {first_hash}, got {fhash}"

    if tmp_path.exists():
        tmp_path.unlink()
