"""Hyperion Security Engine — dependency vulnerability checker backed by OSV.dev."""

from __future__ import annotations

import json
import logging
import math
import re
import urllib.error
import urllib.request
from typing import Any

__all__ = ["check_dependencies", "check_dependencies_with_status", "parse_requirements"]

logger = logging.getLogger(__name__)

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_REQUEST_TIMEOUT_SECONDS = 5
_SUMMARY_MAX_LENGTH = 120

_SEVERITY_LEVELS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MODERATE": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
}

_CVSS_V3_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_UNCHANGED": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_CHANGED": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_PIN_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9.,_-]+\])?)\s*"
    r"(==|>=|~=)\s*([0-9][A-Za-z0-9.*_!+-]*)"
)


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Extract (package, version) pairs from requirements text.

    Handles ==, >=, ~= pins. Comments, blank lines, env markers, extras,
    and unpinned requirements are skipped gracefully.
    """
    pins: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        line = line.split(";", 1)[0].strip()
        match = _PIN_PATTERN.match(line)
        if not match:
            continue
        name = match.group(1).split("[", 1)[0]
        version = match.group(3).rstrip(".*")
        if not version:
            continue
        pins.append((name, version))
    return pins


def _cvss_base_score(vector: str) -> float | None:
    """Compute the CVSS v3 base score from a vector string like
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'. Returns None if the
    vector is malformed or missing required metrics."""
    parts = vector.strip().split("/")
    if parts and parts[0].upper().startswith("CVSS:"):
        parts = parts[1:]
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()
    try:
        av = _CVSS_V3_METRICS["AV"][metrics["AV"]]
        ac = _CVSS_V3_METRICS["AC"][metrics["AC"]]
        ui = _CVSS_V3_METRICS["UI"][metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr_table = "PR_CHANGED" if scope_changed else "PR_UNCHANGED"
        pr = _CVSS_V3_METRICS[pr_table][metrics["PR"]]
        c = _CVSS_V3_METRICS["CIA"][metrics["C"]]
        i = _CVSS_V3_METRICS["CIA"][metrics["I"]]
        a = _CVSS_V3_METRICS["CIA"][metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return min(math.ceil(raw * 10) / 10, 10.0)


def _level_from_score(score: Any) -> str | None:
    if score is None:
        return None
    text = str(score).strip()
    numeric = re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", text)
    if numeric:
        base = float(text)
    elif "/" in text or text.upper().startswith("CVSS:"):
        base = _cvss_base_score(text)
        if base is None:
            return None
    else:
        return None
    if base >= 9.0:
        return "Critical"
    if base >= 7.0:
        return "High"
    if base >= 4.0:
        return "Medium"
    if base > 0.0:
        return "Low"
    return None


def _severity_of(vuln: dict[str, Any]) -> str:
    # Prefer OSV's database_specific severity level when present.
    database_specific = vuln.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity.upper() in _SEVERITY_LEVELS:
            return _SEVERITY_LEVELS[severity.upper()]
    severities = vuln.get("severity")
    if isinstance(severities, list):
        for entry in severities:
            if isinstance(entry, dict):
                level = _level_from_score(entry.get("score"))
                if level:
                    return level
    return "Unknown"


def _summary_of(vuln: dict[str, Any]) -> str:
    summary = vuln.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()
    details = vuln.get("details")
    if isinstance(details, str) and details.strip():
        text = " ".join(details.split())
        if len(text) > _SUMMARY_MAX_LENGTH:
            return text[: _SUMMARY_MAX_LENGTH - 1].rstrip() + "…"
        return text
    return ""


_ID_PREFIX_PRIORITY = ("GHSA", "PYSEC", "CVE")


def _vuln_id_rank(vuln_id: str) -> int:
    for index, prefix in enumerate(_ID_PREFIX_PRIORITY):
        if vuln_id.startswith(prefix + "-"):
            return index
    return len(_ID_PREFIX_PRIORITY)


def _alias_keys(vuln: dict[str, Any]) -> set[str]:
    keys = {str(vuln.get("id", ""))}
    aliases = vuln.get("aliases")
    if isinstance(aliases, list):
        keys.update(alias for alias in aliases if isinstance(alias, str))
    keys.discard("")
    return keys


def _dedupe_vulns(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse OSV entries that are aliases of the same advisory
    (GHSA-*/PYSEC-*/CVE-* describing one vulnerability) into one entry,
    keeping a canonical representative whose id prefers GHSA."""
    groups: list[tuple[set[str], list[dict[str, Any]]]] = []
    for vuln in vulns:
        keys = _alias_keys(vuln)
        target = None
        for group_keys, members in groups:
            if keys & group_keys:
                target = (group_keys, members)
                break
        if target is None:
            groups.append((keys, [vuln]))
        else:
            target[0].update(keys)
            target[1].append(vuln)
    deduped: list[dict[str, Any]] = []
    for _group_keys, members in groups:
        candidates = [str(member.get("id", "")) for member in members if member.get("id")]
        canonical_id = (
            min(candidates, key=_vuln_id_rank) if candidates else "UNKNOWN"
        )
        representative = next(
            (m for m in members if str(m.get("id", "")) == canonical_id),
            members[0],
        )
        merged = dict(representative)
        merged["id"] = canonical_id
        deduped.append(merged)
    return deduped


def _fixed_version_of(vuln: dict[str, Any]) -> str | None:
    for affected in vuln.get("affected", []):
        package = affected.get("package")
        if not isinstance(package, dict) or package.get("ecosystem") != "PyPI":
            continue
        for version_range in affected.get("ranges", []):
            if version_range.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for event in version_range.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _query_osv(name: str, version: str) -> list[dict[str, Any]]:
    payload = json.dumps(
        {
            "package": {"name": name, "ecosystem": "PyPI"},
            "version": version,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        _OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
        body = json.loads(response.read().decode("utf-8"))
    vulns = body.get("vulns")
    return vulns if isinstance(vulns, list) else []


def check_dependencies_with_status(requirements_path: str) -> tuple[list[dict], bool]:
    """Check every pinned requirement against OSV.dev.

    Returns (findings, offline_mode). offline_mode is True only when every
    package lookup failed due to a network-level error, meaning the API was
    entirely unreachable and an empty result does NOT mean "clean".
    """
    # utf-8-sig strips a leading UTF-8 BOM if present (PowerShell-written
    # files have one); otherwise identical to utf-8. Without this the BOM
    # glues onto the first package name, the pin regex silently skips the
    # whole line, and every vulnerability on that package is lost.
    with open(requirements_path, "r", encoding="utf-8-sig") as fh:
        pins = parse_requirements(fh.read())

    findings: list[dict] = []
    failed_lookups = 0

    for name, version in pins:
        try:
            vulns = _query_osv(name, version)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            failed_lookups += 1
            logger.warning(
                "lookup_failed: OSV query raised %s for %s==%s: %s",
                type(exc).__name__,
                name,
                version,
                exc,
            )
            continue

        for vuln in _dedupe_vulns(vulns):
            findings.append(
                {
                    "package": name,
                    "installed_version": version,
                    "vuln_id": str(vuln.get("id", "UNKNOWN")),
                    "severity": _severity_of(vuln),
                    "summary": _summary_of(vuln),
                    "fixed_version": _fixed_version_of(vuln),
                }
            )

    offline_mode = len(pins) > 0 and failed_lookups == len(pins)
    return findings, offline_mode


def check_dependencies(requirements_path: str) -> list[dict]:
    """Return vulnerability findings for a requirements.txt file.

    Use check_dependencies_with_status() to distinguish a genuinely clean
    scan from an offline scan where the OSV API was unreachable.
    """
    findings, _offline_mode = check_dependencies_with_status(requirements_path)
    return findings
