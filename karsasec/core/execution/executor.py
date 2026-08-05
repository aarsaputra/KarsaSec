"""RuleExecutor orchestrating ASTWalker, RuleIndexer, ASTMatcher, EvidenceCollector, and FindingFactory."""

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union

from karsasec.core.execution.context import ScanContext
from karsasec.core.execution.errors import ExecutionError
from karsasec.core.execution.indexer import RuleIndexer
from karsasec.core.execution.result import ExecutionResult
from karsasec.core.finding.collector import EvidenceCollector, evidence_collector
from karsasec.core.finding.factory import FindingFactory, finding_factory
from karsasec.core.finding.model import Finding
from karsasec.parser.ast import ASTWalker, VisitorContext
from karsasec.parser.ast_nodes import FileNode
from karsasec.rules.matcher import ASTMatcher, CompiledRule, ast_matcher
from karsasec.rules.schema import Rule
from karsasec.semantic.resolver import SemanticResolver

class RuleExecutor:
    """Orchestrates streaming AST traversal, indexed rule evaluation, evidence collection, and finding deduplication."""

    def __init__(
        self,
        walker: Optional[ASTWalker] = None,
        matcher: Optional[ASTMatcher] = None,
        collector: Optional[EvidenceCollector] = None,
        factory: Optional[FindingFactory] = None,
    ) -> None:
        self.walker = walker or ASTWalker()
        self.matcher = matcher or ASTMatcher()
        self.collector = collector or evidence_collector
        self.factory = factory or finding_factory

    def execute_scan(
        self,
        scan_context: ScanContext,
        rules: List[Union[Rule, CompiledRule]],
    ) -> ExecutionResult:
        """Executes static analysis scan over a ScanContext.

        Args:
            scan_context: Context containing target FileNode, mandatory source_bytes, and metadata.
            rules: List of raw Rule or pre-compiled CompiledRule instances.

        Returns:
            ExecutionResult: Deduplicated findings and performance metrics.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()

        indexer = RuleIndexer(rules)
        resolver = SemanticResolver()
        semantic_graph = resolver.resolve_file(scan_context.file_node)

        visitor_ctx = VisitorContext(
            file_node=scan_context.file_node,
            symbol_table=scan_context.symbol_table,
            language=scan_context.language,
            file_path=scan_context.file_path,
            semantic_graph=semantic_graph,
        )

        file_path = scan_context.file_path or scan_context.file_node.file_path or Path("unknown")
        seen_fingerprints: Dict[str, Finding] = {}
        errors: List[str] = []
        nodes_count = 0

        for node in self.walker.walk(scan_context.file_node):
            nodes_count += 1
            candidate_rules = indexer.get_candidate_rules(node.node_type)

            for compiled_rule in candidate_rules:
                try:
                    match_res = self.matcher.match(
                        node=node,
                        rule=compiled_rule,
                        context=visitor_ctx,
                        source_bytes=scan_context.source_bytes,
                    )

                    if match_res.matched:
                        evidence = self.collector.extract_evidence(node, scan_context.source_bytes)
                        finding = self.factory.create_finding(
                            rule=compiled_rule.rule,
                            file_path=file_path,
                            evidence=evidence,
                            match_result=match_res,
                        )
                        # Deduplication by fingerprint
                        if finding.fingerprint not in seen_fingerprints:
                            seen_fingerprints[finding.fingerprint] = finding

                except ExecutionError as err:
                    errors.append(f"Rule '{compiled_rule.id}' error on node '{node.node_id}': {str(err)}")
                except Exception as err:
                    errors.append(f"Unexpected error in rule '{compiled_rule.id}' on node '{node.node_id}': {str(err)}")

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ExecutionResult(
            scan_id=scan_id,
            timestamp=timestamp,
            files_scanned=1,
            rules_checked=len(rules),
            nodes_processed=nodes_count,
            findings=tuple(seen_fingerprints.values()),
            execution_time_ms=elapsed_ms,
            errors=tuple(errors),
            statistics=self.matcher.statistics,
        )

# Global default executor instance
rule_executor = RuleExecutor()
