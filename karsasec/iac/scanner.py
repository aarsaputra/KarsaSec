"""Infrastructure as Code (IaC) Scanner bridging to native AST Parsers and Rule Engine v2."""

from pathlib import Path
from typing import List, Optional

from karsasec.core.execution import ScanContext, rule_executor
from karsasec.rules.enums import Severity
from karsasec.rules.finding import Finding
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.parser.docker_parser import docker_parser_plugin
from karsasec.parser.k8s_parser import k8s_parser_plugin
from karsasec.parser.github_actions_parser import gha_parser_plugin


class IaCScanner:
    """Convenience scanner wrapper for IaC files delegating to standard Rule Engine v2."""

    def __init__(self) -> None:
        self.loader = YAMLRuleLoader()
        self.docker_rules = self.loader.load_directory(Path("karsasec/rules/patterns/docker"))
        self.k8s_rules = self.loader.load_directory(Path("karsasec/rules/patterns/kubernetes"))
        self.gha_rules = self.loader.load_directory(Path("karsasec/rules/patterns/github_actions"))

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scans Dockerfile, Kubernetes, or GitHub Actions YAML files using native AST parsers and rule engine."""
        path = file_path.resolve()
        if not path.exists() or not path.is_file():
            return []

        filename = path.name.lower()
        source_bytes = path.read_bytes()

        if filename == "dockerfile" or filename.startswith("dockerfile."):
            parse_res = docker_parser_plugin.parse_file(path)
            if parse_res.root:
                ctx = ScanContext(
                    file_node=parse_res.root,
                    source_bytes=source_bytes,
                    file_path=path,
                    language="Dockerfile",
                )
                res = rule_executor.execute_scan(ctx, self.docker_rules)
                return list(res.findings)

        elif path.suffix in (".yaml", ".yml"):
            content = source_bytes.decode("utf-8", errors="ignore")
            if ".github/workflows" in str(path) or ("on:" in content and "jobs:" in content):
                parse_res = gha_parser_plugin.parse_file(path)
                if parse_res.root:
                    ctx = ScanContext(
                        file_node=parse_res.root,
                        source_bytes=source_bytes,
                        file_path=path,
                        language="GitHub-Actions",
                    )
                    res = rule_executor.execute_scan(ctx, self.gha_rules)
                    return list(res.findings)
            else:
                parse_res = k8s_parser_plugin.parse_file(path)
                if parse_res.root:
                    ctx = ScanContext(
                        file_node=parse_res.root,
                        source_bytes=source_bytes,
                        file_path=path,
                        language="Kubernetes",
                    )
                    res = rule_executor.execute_scan(ctx, self.k8s_rules)
                    return list(res.findings)

        return []
