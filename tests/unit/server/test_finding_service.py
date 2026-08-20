"""Unit tests for FindingService (determinism contract)."""

from __future__ import annotations


from karsasec.server.services.finding_service import FindingService, _severity_rank
from karsasec.server.dto.finding import FindingDTO


class TestSeverityRank:
    def test_critical_is_lowest_rank(self):
        assert _severity_rank("CRITICAL") < _severity_rank("HIGH")

    def test_high_less_than_medium(self):
        assert _severity_rank("HIGH") < _severity_rank("MEDIUM")

    def test_medium_less_than_low(self):
        assert _severity_rank("MEDIUM") < _severity_rank("LOW")

    def test_low_less_than_info(self):
        assert _severity_rank("LOW") < _severity_rank("INFO")

    def test_unknown_severity_gets_high_rank(self):
        assert _severity_rank("UNKNOWN") == 99


class TestFindingService:
    def _make_dto(self, fid, severity, path, line) -> FindingDTO:
        return FindingDTO(
            finding_id=fid, rule_id="R1", severity=severity,
            file_path=path, line_number=line,
        )

    def test_empty_service_returns_empty_list(self):
        svc = FindingService()
        result = svc.list_findings()
        assert result.items == []
        assert result.pagination.total == 0

    def test_pagination_meta_correct(self):
        svc = FindingService()
        svc._findings = [
            self._make_dto(f"f{i}", "LOW", "a.py", i) for i in range(5)
        ]
        result = svc.list_findings(page=1, page_size=3)
        assert result.pagination.total == 5
        assert len(result.items) == 3

    def test_deterministic_sort_by_severity_then_path_then_line(self):
        svc = FindingService()
        svc._findings = [
            self._make_dto("f3", "LOW", "b.py", 10),
            self._make_dto("f1", "CRITICAL", "a.py", 5),
            self._make_dto("f2", "HIGH", "a.py", 2),
        ]
        result = svc.list_findings()
        ids = [f.finding_id for f in result.items]
        assert ids == ["f1", "f2", "f3"]

    def test_sort_stable_on_same_severity_uses_filepath(self):
        svc = FindingService()
        svc._findings = [
            self._make_dto("f2", "MEDIUM", "z.py", 1),
            self._make_dto("f1", "MEDIUM", "a.py", 1),
        ]
        result = svc.list_findings()
        assert result.items[0].finding_id == "f1"

    def test_sort_stable_on_same_severity_path_uses_line(self):
        svc = FindingService()
        svc._findings = [
            self._make_dto("f2", "HIGH", "a.py", 20),
            self._make_dto("f1", "HIGH", "a.py", 5),
        ]
        result = svc.list_findings()
        assert result.items[0].finding_id == "f1"

    def test_get_finding_returns_correct_item(self):
        svc = FindingService()
        svc._findings = [self._make_dto("f99", "LOW", "x.py", 1)]
        result = svc.get_finding("f99")
        assert result is not None
        assert result.finding_id == "f99"

    def test_get_finding_returns_none_for_unknown_id(self):
        svc = FindingService()
        assert svc.get_finding("nonexistent") is None

    def test_filter_by_scan_id(self):
        svc = FindingService()
        svc._findings = [
            FindingDTO(finding_id="f1", rule_id="R", severity="LOW",
                       file_path="a.py", line_number=1, scan_id="scan-A"),
            FindingDTO(finding_id="f2", rule_id="R", severity="LOW",
                       file_path="b.py", line_number=1, scan_id="scan-B"),
        ]
        result = svc.list_findings(scan_id="scan-A")
        assert len(result.items) == 1
        assert result.items[0].finding_id == "f1"
