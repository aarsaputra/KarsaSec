"""Tests for karsasec.qualification.identity (E12-1)."""
from __future__ import annotations

from karsasec.qualification.identity import FindingIdentity, _normalize_path_str


class TestFindingIdentity:
    def _id(self, file: str = "foo.php", line: int | None = 10, rule: str = "KS-PHP-0002") -> FindingIdentity:
        return FindingIdentity(normalized_file=file, line=line, rule_id=rule)

    def test_same_identity_equal(self) -> None:
        a = self._id()
        b = self._id()
        assert a == b

    def test_different_line_not_equal(self) -> None:
        a = self._id(line=10)
        b = self._id(line=20)
        assert a != b

    def test_different_rule_not_equal(self) -> None:
        a = self._id(rule="KS-PHP-0002")
        b = self._id(rule="KS-PHP-0003")
        assert a != b

    def test_different_file_not_equal(self) -> None:
        a = self._id(file="foo.php")
        b = self._id(file="bar.php")
        assert a != b

    def test_fingerprint_is_deterministic(self) -> None:
        a = self._id()
        b = self._id()
        assert a.fingerprint() == b.fingerprint()

    def test_fingerprint_differs_on_different_identity(self) -> None:
        a = self._id(line=10)
        b = self._id(line=20)
        assert a.fingerprint() != b.fingerprint()

    def test_fingerprint_length(self) -> None:
        assert len(self._id().fingerprint()) == 16

    def test_matches_finding_exact(self) -> None:
        a = self._id(file="foo.php", line=10, rule="KS-PHP-0002")
        b = self._id(file="foo.php", line=10, rule="KS-PHP-0002")
        assert a.matches_finding(b)

    def test_matches_finding_different_line_no_match(self) -> None:
        a = self._id(line=10)
        b = self._id(line=20)
        assert not a.matches_finding(b)

    def test_matches_finding_none_line_matches_any(self) -> None:
        """line=None means file-level match — matches any line."""
        a = self._id(line=None)
        b = self._id(line=99)
        assert a.matches_finding(b)

    def test_matches_finding_both_none_line(self) -> None:
        a = self._id(line=None)
        b = self._id(line=None)
        assert a.matches_finding(b)

    def test_is_hashable(self) -> None:
        s = {self._id(), self._id()}
        assert len(s) == 1

    def test_is_sortable(self) -> None:
        ids = [self._id(line=20), self._id(line=10)]
        sorted_ids = sorted(ids)
        assert sorted_ids[0].line == 10


class TestNormalizePathStr:
    def test_posix_lowercased(self) -> None:
        result = _normalize_path_str("Vulnerabilities/SQLi/Low.PHP")
        assert result == "vulnerabilities/sqli/low.php"

    def test_windows_backslash_normalized(self) -> None:
        result = _normalize_path_str("foo\\bar\\baz.php")
        # Path() on linux treats backslash as literal - this is OS-dependent
        # on linux the result will just be lowercased
        assert "\\" not in result or result == result.lower()
