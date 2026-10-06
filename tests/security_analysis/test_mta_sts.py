"""MTA-STS discovery, policy modes, failure handling, and pipeline integration."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception
import httpx
import pytest
import respx

from mail_municipalities.security_analysis import mta_sts, runner
from mail_municipalities.security_analysis.models import MtaStsSummary

URL = "https://mta-sts.example.ch/.well-known/mta-sts.txt"


def policy(mode: str = "enforce") -> str:
    return f"version: STSv1\nmode: {mode}\nmx: *.example.ch\nmax_age: 86400\n"


@pytest.fixture
def discovery(monkeypatch):
    lookup = AsyncMock(return_value=[SimpleNamespace(strings=(b"v=STSv1; ", b"id=123"))])
    monkeypatch.setattr(mta_sts, "resolve_robust", lookup)
    return lookup


@pytest.mark.parametrize("mode", ["testing", "enforce", "none"])
@respx.mock
async def test_policy_modes(discovery, mode):
    route = respx.get(URL).respond(200, text=policy(mode), headers={"content-type": "text/plain; charset=utf-8"})
    async with httpx.AsyncClient() as client:
        result = await mta_sts.check_mta_sts("example.ch", client)
    assert result.status == mode
    assert result.error is None
    assert route.call_count == 1
    discovery.assert_awaited_once_with("_mta-sts.example.ch", "TXT", raise_on_failure=True)


@pytest.mark.parametrize("answer", [None, [], [SimpleNamespace(strings=(b"unrelated TXT",))]])
@respx.mock
async def test_not_configured_does_not_fetch(discovery, answer):
    discovery.return_value = answer
    async with httpx.AsyncClient() as client:
        result = await mta_sts.check_mta_sts("example.ch", client)
    assert result.status == "not_configured"
    assert not respx.calls


@respx.mock
async def test_dns_failure_is_not_absence(discovery):
    discovery.side_effect = dns.exception.DNSException("timed out")
    async with httpx.AsyncClient() as client:
        result = await mta_sts.check_mta_sts("example.ch", client)
    assert result.status == "unreachable"
    assert not respx.calls


@pytest.mark.parametrize(
    "records",
    [
        [b"v=STSv1; id=123", b"v=STSv1; id=456"],
        [b"v=STSv1; missing=id"],
        [b"v=STSv1; id=bad-id"],
        [b"v=STSv1; id=" + b"a" * 33],
        [b"v=STSv1; id=123; garbage"],
        [b"v=STSv1; id=123; extra=\xff"],
    ],
)
@respx.mock
async def test_invalid_discovery_does_not_fetch(discovery, records):
    discovery.return_value = [SimpleNamespace(strings=(record,)) for record in records]
    async with httpx.AsyncClient() as client:
        result = await mta_sts.check_mta_sts("example.ch", client)
    assert result.status == "invalid"
    assert result.error
    assert not respx.calls


@pytest.mark.parametrize(
    "body",
    [
        policy("bogus"),
        policy().replace("version: STSv1", "version: STSv2"),
        policy().replace("max_age: 86400", "max_age: -1"),
        policy().replace("max_age: 86400", "max_age: 31557601"),
        policy().replace("max_age: 86400\n", ""),
        policy().replace("mx: *.example.ch\n", ""),
        policy().replace("mx: *.example.ch", "mx: mail.*.example.ch"),
        policy().replace("mx: *.example.ch", "mx: -bad.example.ch"),
        policy().replace("mx: *.example.ch", "mx: " + "a" * 64 + ".ch"),
        policy() + "\nmode: testing\n",
        b"version: STSv1\nmode: enforce\n\xff",
        "<html>mode: enforce</html>",
        policy() + "x: " + "a" * (64 * 1024),
    ],
)
@respx.mock
async def test_invalid_policy(discovery, body):
    respx.get(URL).respond(200, content=body, headers={"content-type": "text/plain"})
    async with httpx.AsyncClient() as client:
        result = await mta_sts.check_mta_sts("example.ch", client)
    assert result.status == "invalid"
    assert result.error


@respx.mock
async def test_extensions_duplicates_and_crlf(discovery):
    discovery.return_value = [SimpleNamespace(strings=(b"v=STSv1; id=123; extra=ok; id=456;",))]
    body = policy("testing") + "mode: enforce\nx-extra: supported\nmx: backup.example.ch\n"
    respx.get(URL).respond(200, text=body.replace("\n", "\r\n"), headers={"content-type": "text/plain"})
    async with httpx.AsyncClient() as client:
        assert (await mta_sts.check_mta_sts("example.ch", client)).status == "testing"


@respx.mock
async def test_none_does_not_require_mx(discovery):
    body = policy("none").replace("mx: *.example.ch\n", "")
    respx.get(URL).respond(200, text=body, headers={"content-type": "text/plain"})
    async with httpx.AsyncClient() as client:
        assert (await mta_sts.check_mta_sts("example.ch", client)).status == "none"


@pytest.mark.parametrize("code,expected", [(301, "invalid"), (404, "invalid"), (503, "unreachable")])
@respx.mock
async def test_http_failures_and_no_redirects(discovery, code, expected):
    respx.get(URL).respond(code, headers={"location": "https://other.example.ch/policy"})
    async with httpx.AsyncClient(follow_redirects=True) as client:
        result = await mta_sts.check_mta_sts("example.ch", client)
    assert result.status == expected
    assert len(respx.calls) == 1


@pytest.mark.parametrize("headers", [{}, {"content-type": "text/html"}])
@respx.mock
async def test_wrong_media_type(discovery, headers):
    respx.get(URL).respond(200, content=policy().encode(), headers=headers)
    async with httpx.AsyncClient() as client:
        assert (await mta_sts.check_mta_sts("example.ch", client)).status == "invalid"


@pytest.mark.parametrize("error", [httpx.ConnectError("certificate verify failed"), httpx.ReadTimeout("timeout")])
@respx.mock
async def test_https_failure(discovery, error):
    respx.get(URL).mock(side_effect=error)
    async with httpx.AsyncClient() as client:
        assert (await mta_sts.check_mta_sts("example.ch", client)).status == "unreachable"


@respx.mock
async def test_exact_subdomain_not_parent(discovery):
    respx.get("https://mta-sts.mail.example.ch/.well-known/mta-sts.txt").respond(
        200, text=policy(), headers={"content-type": "text/plain"}
    )
    async with httpx.AsyncClient() as client:
        assert (await mta_sts.check_mta_sts("mail.example.ch", client)).status == "enforce"
    discovery.assert_awaited_once_with("_mta-sts.mail.example.ch", "TXT", raise_on_failure=True)


async def test_unique_domains(monkeypatch):
    check = AsyncMock(return_value=MtaStsSummary(status="not_configured"))
    monkeypatch.setattr(mta_sts, "check_mta_sts", check)
    results = await mta_sts.scan_mta_sts(["example.ch", "example.ch", "", "other.ch"])
    assert set(results) == {"example.ch", "other.ch"}
    assert check.await_count == 2


def test_full_runner_integration(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    domains_path = tmp_path / "domains_ch.json"
    domains_path.write_text(
        json.dumps(
            {
                "municipalities": [
                    {"code": "1", "name": "A", "emails": ["example.ch"]},
                    {"code": "2", "name": "B", "emails": ["example.ch"]},
                    {"code": "3", "name": "C", "emails": ["missing.ch"]},
                    {"code": "4", "name": "D", "emails": []},
                ]
            }
        )
    )
    evaluator = tmp_path / "evaluation.json"
    evaluator.write_text("[]")  # Policy results survive even without legacy scanner rows.
    monkeypatch.setattr(runner, "_SECURITY_TEST_DIR", tmp_path)
    monkeypatch.setattr(runner, "find_docker_compose", lambda: ["docker", "compose"])
    monkeypatch.setattr(runner, "ensure_env", lambda *_: None)
    monkeypatch.setattr(runner, "run_docker_scanner", lambda *_: None)
    monkeypatch.setattr(runner, "run_docker_evaluator", lambda *_: evaluator)
    check = AsyncMock(
        return_value={
            "example.ch": MtaStsSummary(status="testing"),
            "missing.ch": MtaStsSummary(status="not_configured"),
        }
    )
    monkeypatch.setattr(runner, "scan_mta_sts", check)
    output_path = tmp_path / "security_ch.json"
    runner.run(domains_path, output_path, cc="ch")
    output = json.loads(output_path.read_text())
    assert output["counts"]["mta_sts_testing"] == 2
    assert output["counts"]["mta_sts_not_configured"] == 1
    assert output["counts"]["scanned"] == 0
    assert output["municipalities"][0]["mta_sts"]["status"] == "testing"
    assert output["municipalities"][3]["mta_sts"] is None
    check.assert_awaited_once()


def test_old_output_remains_unchecked():
    from mail_municipalities.security_analysis.models import MunicipalitySecurity

    municipality = MunicipalitySecurity(code="1", name="A", region="ZH", domain="example.ch")
    assert municipality.mta_sts is None
