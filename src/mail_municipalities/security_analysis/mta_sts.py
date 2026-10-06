"""Discover the published MTA-STS policy mode using DNS and HTTPS (RFC 8461)."""

from __future__ import annotations

import asyncio
import re
from typing import cast

import dns.exception
import httpx

from mail_municipalities.core.dns import resolve_robust

from .models import MtaStsStatus, MtaStsSummary

_MAX_POLICY_BYTES = 64 * 1024
_FIELD_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}"
_MX_PATTERN = re.compile(
    r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)


def _validate_record(record: str) -> None:
    """Validate discovery syntax; unknown fields and later duplicates are ignored."""
    fields: dict[str, str] = {}
    parts = record.split(";")
    if parts[-1].strip(" \t") == "":
        parts.pop()
    for part in parts:
        match = re.fullmatch(rf"[ \t]*({_FIELD_NAME})=([\x21-\x3a\x3c\x3e-\x7e]+)[ \t]*", part)
        if not match:
            raise ValueError("Invalid MTA-STS discovery record")
        fields.setdefault(match[1], match[2])
    if fields.get("v") != "STSv1" or not re.fullmatch(r"[A-Za-z0-9]{1,32}", fields.get("id", "")):
        raise ValueError("Discovery record requires v=STSv1 and a valid id")


def _policy_mode(body: bytes) -> MtaStsStatus:
    """Validate policy syntax and return its declared mode, without SMTP probing."""
    text = body.decode("utf-8")
    fields: dict[str, str] = {}
    mx: list[str] = []
    # Only LF and CRLF delimit lines; blank interior lines are not policy fields.
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    for line in lines:
        line = line.removesuffix("\r")
        match = re.fullmatch(rf"({_FIELD_NAME}):[ \t]*([^\x00-\x1f\x7f]+?)[ \t]*", line)
        if not match:
            raise ValueError("Invalid MTA-STS policy line")
        key, value = match[1], match[2]
        if key == "mx":
            mx.append(value)
        else:
            fields.setdefault(key, value)
    if fields.get("version") != "STSv1":
        raise ValueError("Policy requires version: STSv1")
    mode = fields.get("mode")
    if mode not in ("testing", "enforce", "none"):
        raise ValueError("Policy requires mode: testing, enforce, or none")
    max_age = fields.get("max_age", "")
    if not re.fullmatch(r"[0-9]{1,10}", max_age) or int(max_age) > 31557600:
        raise ValueError("Policy requires a valid max_age (0–31557600 seconds)")
    if mode != "none" and not mx:
        raise ValueError("Testing and enforce policies require at least one mx field")
    if any(len(pattern.removeprefix("*.")) > 253 or not _MX_PATTERN.fullmatch(pattern) for pattern in mx):
        raise ValueError("Invalid MX pattern in policy")
    return cast(MtaStsStatus, mode)


async def check_mta_sts(domain: str, client: httpx.AsyncClient) -> MtaStsSummary:
    """Check the exact email domain; absence and transient failures stay distinct."""
    try:
        answer = await resolve_robust(f"_mta-sts.{domain}", "TXT", raise_on_failure=True)
    except dns.exception.DNSException:
        return MtaStsSummary(status="unreachable", error="DNS lookup failed")
    records = (
        [] if answer is None else [b"".join(record.strings).decode("ascii", errors="replace") for record in answer]
    )
    records = [record for record in records if re.match(r"v=STSv1(?:[ \t]*;|$)", record)]
    if not records:
        return MtaStsSummary(status="not_configured")
    if len(records) != 1:
        return MtaStsSummary(status="invalid", error="Multiple MTA-STS discovery records")
    try:
        _validate_record(records[0])
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        async with client.stream("GET", url, follow_redirects=False, timeout=15.0) as response:
            if response.status_code != 200:
                status = "unreachable" if response.status_code >= 500 else "invalid"
                return MtaStsSummary(status=status, error=f"Policy endpoint returned HTTP {response.status_code}")
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type != "text/plain":
                raise ValueError("Policy must be served as text/plain")
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=8192):
                body.extend(chunk)
                if len(body) > _MAX_POLICY_BYTES:
                    raise ValueError("Policy exceeds 64 KiB")
        return MtaStsSummary(status=_policy_mode(bytes(body)))
    except ValueError as exc:
        return MtaStsSummary(status="invalid", error=str(exc))
    except httpx.HTTPError:
        return MtaStsSummary(
            status="unreachable", error="HTTPS policy fetch failed (connection, timeout, or TLS error)"
        )


async def scan_mta_sts(domains: list[str]) -> dict[str, MtaStsSummary]:
    """Scan each unique email domain once, with bounded DNS/HTTP concurrency."""
    semaphore = asyncio.Semaphore(20)
    async with httpx.AsyncClient() as client:

        async def check(domain: str) -> tuple[str, MtaStsSummary]:
            async with semaphore:
                return domain, await check_mta_sts(domain, client)

        return dict(await asyncio.gather(*(check(domain) for domain in sorted(set(domains)) if domain)))
