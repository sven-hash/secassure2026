"""MTA-STS-only scans preserve other checks and work without Docker."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from typer.testing import CliRunner

from mail_municipalities.cli import _scan_app, app
from mail_municipalities.security_analysis import runner
from mail_municipalities.security_analysis.models import MtaStsSummary


@pytest.fixture
def scan(monkeypatch):
    scan = AsyncMock(
        return_value={
            "old.ch": MtaStsSummary(status="enforce"),
            "missing.ch": MtaStsSummary(status="not_configured"),
        }
    )
    monkeypatch.setattr(runner, "scan_mta_sts", scan)
    monkeypatch.setattr(runner, "find_docker_compose", Mock(side_effect=AssertionError("Docker must not be used")))
    monkeypatch.setattr(runner, "_SECURITY_TEST_DIR", Path("/nonexistent/scanner"))
    return scan


@pytest.fixture
def existing(tmp_path):
    data = {
        "generated": "2026-04-09T00:00:00Z",
        "commit": "original",
        "total": 3,
        "custom_metadata": {"preserve": True},
        "counts": {"scanned": 1, "spf": 1, "mta_sts_testing": 99},
        "municipalities": [
            {
                "code": "1",
                "name": "A",
                "region": "ZH",
                "domain": "old.ch",
                "scan_valid": True,
                "mx_records": ["mx.old.ch"],
                "dane": {"supported": True},
                "dss": {"has_spf": True, "has_dmarc": True},
                "override": {"source": "manual"},
                "unknown_field": "preserve",
                "mta_sts": {"status": "testing", "error": None},
            },
            {"code": "2", "name": "B", "domain": "missing.ch", "scan_valid": False},
            {"code": "3", "name": "C", "domain": "", "scan_valid": False},
        ],
    }
    output = tmp_path / "security_ch.json"
    output.write_text(json.dumps(data))
    output.chmod(0o640)
    return output, data


def test_preserves_existing_results_without_domain_file(scan, existing, tmp_path):
    output, original = existing
    runner.run(tmp_path / "missing_domains.json", output, cc="ch", mta_sts_only=True)
    updated = json.loads(output.read_text())
    assert updated["generated"] == original["generated"]
    assert updated["commit"] == "original"
    assert updated["custom_metadata"] == original["custom_metadata"]
    assert updated["total"] == 3
    assert updated["mta_sts_generated"]
    assert updated["counts"]["scanned"] == 1
    assert updated["counts"]["spf"] == 1
    assert updated["counts"]["mta_sts_enforce"] == 1
    assert updated["counts"]["mta_sts_not_configured"] == 1
    assert updated["counts"]["mta_sts_testing"] == 0
    for before, after in zip(original["municipalities"], updated["municipalities"], strict=True):
        assert {k: v for k, v in before.items() if k != "mta_sts"} == {k: v for k, v in after.items() if k != "mta_sts"}
    assert updated["municipalities"][2]["mta_sts"] is None
    scan.assert_awaited_once_with(["old.ch", "missing.ch"])
    assert output.stat().st_mode & 0o777 == 0o640
    assert sorted(p.name for p in tmp_path.iterdir()) == ["security_ch.json"]


def test_scans_existing_domain_instead_of_new_mapping(scan, existing, tmp_path):
    output, _ = existing
    domains = tmp_path / "domains_ch.json"
    domains.write_text(json.dumps({"municipalities": [{"code": "1", "name": "A", "emails": ["new.ch"]}]}))
    runner.run(domains, output, cc="ch", mta_sts_only=True)
    scan.assert_awaited_once_with(["old.ch", "missing.ch"])
    assert json.loads(output.read_text())["municipalities"][0]["domain"] == "old.ch"


def test_creates_map_data_from_domains_without_other_checks(scan, tmp_path):
    domains = tmp_path / "domains_ch.json"
    domains.write_text(
        json.dumps(
            {
                "municipalities": [
                    {"code": "2", "name": "B", "region": "ZH", "emails": []},
                    {"code": "1", "name": "A", "region": "BE", "emails": ["old.ch"]},
                ]
            }
        )
    )
    output = tmp_path / "nested" / "security_ch.json"
    runner.run(domains, output, cc="ch", mta_sts_only=True)
    data = json.loads(output.read_text())
    assert data["total"] == 2
    assert data["counts"]["scanned"] == 0
    assert data["counts"]["spf"] == 0
    assert data["counts"]["mta_sts_enforce"] == 1
    first = data["municipalities"][0]
    assert first["code"] == "1"
    assert first["mta_sts"]["status"] == "enforce"
    assert first["dss"] is None
    assert first["dane"] is None
    assert first["scan_valid"] is False
    assert data["municipalities"][1]["mta_sts"] is None
    scan.assert_awaited_once_with(["old.ch"])


def test_failure_keeps_original_file(scan, existing, tmp_path):
    output, _ = existing
    original_bytes = output.read_bytes()
    scan.side_effect = RuntimeError("scan interrupted")
    with pytest.raises(RuntimeError, match="interrupted"):
        runner.run(tmp_path / "domains_ch.json", output, cc="ch", mta_sts_only=True)
    assert output.read_bytes() == original_bytes


def test_failed_write_keeps_original_file(scan, existing, tmp_path, monkeypatch):
    output, _ = existing
    original_bytes = output.read_bytes()
    monkeypatch.setattr(runner.json, "dump", Mock(side_effect=OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        runner.run(tmp_path / "domains_ch.json", output, cc="ch", mta_sts_only=True)
    assert output.read_bytes() == original_bytes
    assert sorted(p.name for p in tmp_path.iterdir()) == ["security_ch.json"]


def test_missing_sources_fail_before_scan(scan, tmp_path):
    with pytest.raises(FileNotFoundError):
        runner.run(tmp_path / "missing.json", tmp_path / "security_ch.json", cc="ch", mta_sts_only=True)
    scan.assert_not_awaited()


@pytest.mark.parametrize("cli, prefix", [(_scan_app, []), (app, ["scan"])])
def test_flag_runs_on_both_entrypoints(cli, prefix, scan, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    domains = tmp_path / "custom-domains"
    domains.mkdir()
    (domains / "domains_ch.json").write_text(
        json.dumps(
            {
                "municipalities": [
                    {"code": "1", "name": "A", "emails": ["old.ch"]},
                ]
            }
        )
    )
    result = CliRunner().invoke(
        cli, [*prefix, "ch", "--mta-sts-only", "--domains-dir", str(domains), "-o", "custom-output"]
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "custom-output" / "security_ch.json").exists()
    scan.assert_awaited_once_with(["old.ch"])


@pytest.mark.parametrize("cli, prefix", [(_scan_app, []), (app, ["scan"])])
def test_default_keeps_full_scan(cli, prefix, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run = Mock()
    monkeypatch.setattr(runner, "run", run)
    result = CliRunner().invoke(cli, [*prefix, "ch"])
    assert result.exit_code == 0, result.output
    run.assert_called_once_with(
        Path("output/domains/domains_ch.json"),
        Path("output/security/security_ch.json"),
        cc="ch",
        verbose=False,
        mta_sts_only=False,
    )
