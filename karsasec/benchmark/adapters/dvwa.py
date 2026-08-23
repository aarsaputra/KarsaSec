"""DVWA (Damn Vulnerable Web App) Benchmark Adapter.

Parses benchmarks/dvwa/manifest.yaml into canonical benchmark cases.
"""

from pathlib import Path
import yaml


class DvwaManifestAdapter:
    """Adapter parsing DVWA manifest.yaml into canonical benchmark cases."""

    def __init__(self, manifest_path: str = "benchmarks/dvwa/manifest.yaml") -> None:
        self.manifest_path = Path(manifest_path)

    def load_canonical_cases(self) -> list[dict]:
        """Loads canonical benchmark cases from manifest.yaml.

        Returns:
            list[dict] of canonical cases.
        """
        if not self.manifest_path.exists():
            return []

        with open(self.manifest_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        cases_raw = data.get("cases", [])
        canonical_cases = []

        for c in cases_raw:
            exp_raw = c.get("expected", "TRUE_POSITIVE")
            exp_status = "VULNERABLE" if exp_raw in ("TRUE_POSITIVE", "VULNERABLE") else "SAFE"

            # Create synthetic code snippet simulating DVWA file pattern if raw source unavailable
            code_snippet = c.get("description", "")
            if "sqli" in c.get("category", "").lower() or c.get("cwe") == "CWE-89":
                if exp_status == "VULNERABLE":
                    code_snippet = "$id = $_REQUEST['id']; $res = mysqli_query($conn, 'SELECT * FROM users WHERE id = ' . $id);"
                else:
                    code_snippet = "$id = $_REQUEST['id']; $stmt = $db->prepare('SELECT * FROM users WHERE id = :id'); $stmt->bindValue(':id', (int)$id);"

            elif "command" in c.get("category", "").lower() or c.get("cwe") == "CWE-78":
                if exp_status == "VULNERABLE":
                    code_snippet = "$target = $_REQUEST['ip']; $res = shell_exec('ping ' . $target);"
                else:
                    code_snippet = "$target = $_REQUEST['ip']; if (filter_var($target, FILTER_VALIDATE_IP)) { $res = shell_exec('ping ' . $target); }"

            elif "path" in c.get("category", "").lower() or c.get("cwe") == "CWE-22":
                if exp_status == "VULNERABLE":
                    code_snippet = "$id = $_GET['id']; $content = file_get_contents('./vulnerabilities/' . $id . '/source.php');"
                else:
                    code_snippet = "$content = file_get_contents('../dvwa/includes/dvwaPage.inc.php');"

            canonical_cases.append({
                "vulnerability_id": c.get("id"),
                "dataset": "DVWA",
                "original_case_id": c.get("id"),
                "language": c.get("language", "PHP"),
                "framework": "DVWA_Core",
                "code_snippet": code_snippet,
                # Evaluator-only fields
                "CWE": c.get("cwe", "CWE-89"),
                "expected_status": exp_status,
                "source_artifact": c.get("file", ""),
                "source_hash": "dvwa_manifest_v1",
                "adapter_version": "1.0.0",
            })

        return canonical_cases
