"""Tests for agent_decoy_secret_tripwire. Tmp dirs only, no network."""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_decoy_secret_tripwire import (  # noqa: E402
    INFIX,
    load_manifest,
    plant,
    scan,
    webhook_payload,
)


def _planted(tmp_path, label="db"):
    rng = random.Random(42)
    return plant(str(tmp_path), label, rng=rng)


def test_plant_creates_missing_directory(tmp_path):
    """Regression: plant() must not crash when the target dir is absent."""
    missing = str(tmp_path / "does" / "not" / "exist")
    assert not os.path.exists(missing)
    path, token = plant(missing, "newdir", rng=random.Random(3))
    assert os.path.exists(path)
    assert os.path.exists(os.path.join(missing, ".decoy-manifest.json")) \
        or load_manifest(missing)


def test_plant_writes_inert_token(tmp_path):
    path, token = _planted(tmp_path)
    assert os.path.exists(path)
    assert INFIX in token
    assert "decoy" in token.lower()


def test_plant_manifest_has_hash_not_token(tmp_path):
    _, token = _planted(tmp_path)
    manifest = load_manifest(str(tmp_path))
    assert "db" in manifest
    h = manifest["db"]["token_sha256"]
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
    assert token not in json.dumps(manifest)


def test_plant_deterministic_with_rng(tmp_path):
    _, t1 = plant(str(tmp_path), "a", rng=random.Random(7))
    _, t2 = plant(str(tmp_path), "b", rng=random.Random(7))
    assert t1 == t2


def test_decoy_kinds(tmp_path):
    for kind in ("github-style", "aws-style", "slack-style"):
        path, token = plant(str(tmp_path), kind, kind=kind,
                            rng=random.Random(1))
        assert INFIX in token or kind == "aws-style"
        assert "decoy" in token.lower() or "AKDA" in token


def test_scan_clean_is_quiet(tmp_path):
    _, token = _planted(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "session.log").write_text("agent ran tool X\nall good\n")
    report = scan(str(logs), str(tmp_path))
    assert report["tripped"] == [] and report["files_scanned"] == 1


def test_scan_trips_on_leaked_token(tmp_path):
    _, token = _planted(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "toolcalls.jsonl").write_text(
        '{"tool": "http", "args": {"key": "%s"}}\n' % token)
    report = scan(str(logs), str(tmp_path))
    assert len(report["tripped"]) == 1
    assert report["tripped"][0]["label"] == "db"
    assert report["tripped"][0]["line"] == 1


def test_scan_ignores_planted_file(tmp_path):
    _planted(tmp_path)
    # The planted file itself must never count as a trip.
    report = scan(str(tmp_path), str(tmp_path))
    assert report["tripped"] == []


def test_webhook_payload():
    trips = [{"label": "db", "file": "f", "line": 3, "context": "c"}]
    p = webhook_payload(trips)
    assert p["event"] == "decoy-secret-tripwire"
    assert "1 decoy" in p["summary"]


def test_main_plant_and_scan(tmp_path, capsys):
    from agent_decoy_secret_tripwire import main
    assert main(["plant", "--dir", str(tmp_path), "--label", "x"]) == 0
    logs = tmp_path / "logs"
    logs.mkdir()
    assert main(["scan", "--log-dir", str(logs),
                 "--plant-dir", str(tmp_path), "--json"]) == 0
