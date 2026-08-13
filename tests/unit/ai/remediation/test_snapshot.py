"""Unit tests for SourceSnapshot and TOCTOU defense (Sprint E13-4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from karsasec.ai.remediation.snapshot import FileSnapshot, SourceSnapshot


def test_01_capture_and_aggregate_hash(tmp_path: Path) -> None:
    f1 = tmp_path / "app.py"
    f1.write_text("print('hello')\n", encoding="utf-8")
    f2 = tmp_path / "utils.py"
    f2.write_text("def helper(): pass\n", encoding="utf-8")

    snap = SourceSnapshot.capture(tmp_path, ("app.py", "utils.py"))

    assert snap.repository_root == str(tmp_path.resolve())
    assert len(snap.file_snapshots) == 2
    assert len(snap.aggregate_hash) == 64

    s_map = {f.relative_path: f for f in snap.file_snapshots}
    assert s_map["app.py"].exists is True
    assert s_map["utils.py"].exists is True


def test_02_snapshot_matching_verification(tmp_path: Path) -> None:
    f1 = tmp_path / "app.py"
    f1.write_text("code v1\n", encoding="utf-8")

    snap1 = SourceSnapshot.capture(tmp_path, ("app.py",))
    snap2 = SourceSnapshot.capture(tmp_path, ("app.py",))

    match, err = snap1.verify_matches(snap2)
    assert match is True
    assert err == "MATCH"


def test_03_toctou_mutation_detection(tmp_path: Path) -> None:
    f1 = tmp_path / "app.py"
    f1.write_text("code v1\n", encoding="utf-8")

    snap1 = SourceSnapshot.capture(tmp_path, ("app.py",))

    # Mutate source file after snapshot
    f1.write_text("code v2 TAMPERED\n", encoding="utf-8")
    snap2 = SourceSnapshot.capture(tmp_path, ("app.py",))

    match, err = snap1.verify_matches(snap2)
    assert match is False
    assert "AGGREGATE_HASH_MISMATCH" in err


def test_04_missing_target_file_handling(tmp_path: Path) -> None:
    snap = SourceSnapshot.capture(tmp_path, ("non_existent.py",))
    assert snap.file_snapshots[0].exists is False
    assert snap.file_snapshots[0].sha256 == "MISSING"


def test_05_path_traversal_rejection(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Path traversal detected"):
        SourceSnapshot.capture(tmp_path, ("../outside.py",))


def test_06_symlink_escape_rejection(tmp_path: Path) -> None:
    outside_dir = tmp_path.parent / "outside_dir"
    outside_dir.mkdir(exist_ok=True)
    outside_file = outside_dir / "secret.py"
    outside_file.write_text("secret_key = 123\n", encoding="utf-8")

    symlink_file = tmp_path / "sym_link.py"
    symlink_file.symlink_to(outside_file)

    with pytest.raises(ValueError, match="(Symlink escape|Path traversal) detected"):
        SourceSnapshot.capture(tmp_path, ("sym_link.py",))


def test_07_file_list_mismatch_verification(tmp_path: Path) -> None:
    f1 = tmp_path / "a.py"
    f1.write_text("a", encoding="utf-8")
    f2 = tmp_path / "b.py"
    f2.write_text("b", encoding="utf-8")

    snap1 = SourceSnapshot.capture(tmp_path, ("a.py",))

    # Create dummy snap2 with different file list
    file_snap_b = FileSnapshot("b.py", 1, "hash_b", True)
    snap2 = SourceSnapshot(
        repository_root=str(tmp_path.resolve()),
        file_snapshots=(file_snap_b,),
        aggregate_hash="diff_hash",
        created_at=snap1.created_at,
    )

    match, err = snap1.verify_matches(snap2)
    assert match is False


def test_08_per_file_sha256_verification(tmp_path: Path) -> None:
    f1 = tmp_path / "a.py"
    f1.write_text("hello", encoding="utf-8")
    h1 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    snap = SourceSnapshot.capture(tmp_path, ("a.py",))
    assert snap.file_snapshots[0].sha256 == h1


def test_09_to_dict_from_dict_roundtrip(tmp_path: Path) -> None:
    f1 = tmp_path / "app.py"
    f1.write_text("print('test')\n", encoding="utf-8")

    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    d = snap.to_dict()
    restored = SourceSnapshot.from_dict(d)

    assert restored == snap


def test_10_sorted_aggregate_hash_determinism(tmp_path: Path) -> None:
    f1 = tmp_path / "a.py"
    f1.write_text("content a", encoding="utf-8")
    f2 = tmp_path / "b.py"
    f2.write_text("content b", encoding="utf-8")

    snap1 = SourceSnapshot.capture(tmp_path, ("a.py", "b.py"))
    snap2 = SourceSnapshot.capture(tmp_path, ("b.py", "a.py"))

    assert snap1.aggregate_hash == snap2.aggregate_hash


def test_11_empty_target_files_snapshot(tmp_path: Path) -> None:
    snap = SourceSnapshot.capture(tmp_path, ())
    assert len(snap.file_snapshots) == 0
    assert len(snap.aggregate_hash) == 64


def test_12_nested_directory_target_snapshot(tmp_path: Path) -> None:
    nested = tmp_path / "src" / "controllers"
    nested.mkdir(parents=True)
    f = nested / "auth.py"
    f.write_text("class Auth: pass\n", encoding="utf-8")

    snap = SourceSnapshot.capture(tmp_path, ("src/controllers/auth.py",))
    assert snap.file_snapshots[0].relative_path == "src/controllers/auth.py"
    assert snap.file_snapshots[0].exists is True


def test_13_file_size_tracking(tmp_path: Path) -> None:
    f1 = tmp_path / "data.txt"
    f1.write_bytes(b"1234567890")

    snap = SourceSnapshot.capture(tmp_path, ("data.txt",))
    assert snap.file_snapshots[0].file_size == 10


def test_14_windows_style_path_normalization(tmp_path: Path) -> None:
    f1 = tmp_path / "sub" / "file.py"
    f1.parent.mkdir()
    f1.write_text("code\n", encoding="utf-8")

    snap = SourceSnapshot.capture(tmp_path, ("sub\\file.py",))
    assert snap.file_snapshots[0].relative_path == "sub/file.py"


def test_15_file_existence_changed_detection(tmp_path: Path) -> None:
    f1 = tmp_path / "temp.py"
    f1.write_text("temp", encoding="utf-8")

    snap1 = SourceSnapshot.capture(tmp_path, ("temp.py",))

    f1.unlink()  # Delete file
    snap2 = SourceSnapshot.capture(tmp_path, ("temp.py",))

    match, err = snap1.verify_matches(snap2)
    assert match is False
