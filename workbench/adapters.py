"""Offline, non-executing parsers for supported scanner result formats.

These parsers deliberately discard raw request/response bodies, code snippets, secret
matches, credentials, curl commands, and other reusable exploit material. They produce
candidate observations only through the workbench adapter contract; they never verify a
finding or execute a scanner.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable
from urllib.parse import urlsplit

from .contracts import ADAPTER_SCHEMA, normalize_adapter_result

MAX_OUTPUT_BYTES = 2_000_000
MAX_FINDINGS = 500
MAX_TEXT = 1000


def _decode(raw: str | bytes) -> str:
    if isinstance(raw, bytes):
        if len(raw) > MAX_OUTPUT_BYTES:
            raise ValueError("scanner output is too large")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("scanner output must be UTF-8") from exc
    elif isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("scanner output is too large")
    else:
        raise ValueError("scanner output must be text or UTF-8 bytes")
    if "\x00" in raw:
        raise ValueError("scanner output contains NUL bytes")
    return raw


def _text(value: Any, fallback: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        value = fallback
    value = " ".join(value.split())
    if not value:
        value = fallback
    return value[:maximum]


def _identity_text(value: Any, fallback: str) -> str:
    """Keep full identity metadata; only presentation fields may be truncated."""
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _occurrence_id(kind: str, *fields: Any) -> str:
    """Hash a typed identity tuple without retaining secret scanner payloads."""
    canonical = json.dumps([kind, *fields], ensure_ascii=True, separators=(",", ":"))
    return kind + ":" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _line(value: Any) -> int | None:
    if type(value) is int and value > 0:
        return value
    return None


def _severity(value: Any, *, semgrep: bool = False) -> str:
    text = str(value or "").strip().lower()
    if semgrep:
        return {"info": "info", "warning": "low", "error": "medium"}.get(text, "info")
    return text if text in {"info", "low", "medium", "high", "critical"} else "info"


def _safe_url_path(value: Any, maximum: int | None = 1000) -> str | None:
    """Extract only an HTTP URL path, with optional display-length bounding."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.path:
        return None
    return parsed.path if maximum is None else parsed.path[:maximum]


def _envelope(
    adapter_id: str,
    version: str,
    status: str,
    coverage: dict[str, Any],
    findings: list[dict[str, Any]],
    error: str | None = None,
) -> dict[str, Any]:
    if len(findings) > MAX_FINDINGS:
        raise ValueError("scanner output contains too many findings")
    payload = {
        "schema": ADAPTER_SCHEMA,
        "adapter": {"id": adapter_id, "version": version},
        "status": status,
        "coverage": coverage,
        "findings": findings,
    }
    if error is not None:
        payload["error"] = error
    return payload


def parse_semgrep_json(
    raw: str | bytes, *, version: str, asset_key: str, adapter_id: str = "semgrep-json"
) -> dict[str, Any]:
    """Parse Semgrep JSON while omitting source snippets and metavariable contents.

    ``adapter_id`` remains ``semgrep-json`` for passive imports. A reviewed execution
    adapter may supply its own fixed identity so execution receipts bind to the runner
    that actually produced the output without changing the parser's minimization rules.
    """
    text = _decode(raw)
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid Semgrep JSON") from exc
    if not isinstance(document, dict) or not isinstance(
        document.get("results", []), list
    ):
        raise ValueError("invalid Semgrep result object")

    scanned = (
        document.get("paths", {}).get("scanned", [])
        if isinstance(document.get("paths"), dict)
        else []
    )
    if not isinstance(scanned, list):
        scanned = []
    errors = document.get("errors", [])
    if not isinstance(errors, list):
        raise ValueError("invalid Semgrep errors field")

    findings = []
    for item in document.get("results", []):
        if not isinstance(item, dict):
            raise ValueError("invalid Semgrep finding")
        extra = item.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}
        check_id = _text(item.get("check_id"), "semgrep/unknown-rule", 160)
        path = _text(item.get("path"), "unknown", 1000)
        start = item.get("start", {}) if isinstance(item.get("start"), dict) else {}
        end = item.get("end", {}) if isinstance(item.get("end"), dict) else {}
        evidence = {
            "path": path,
            "start_line": _line(start.get("line")),
            "start_col": _line(start.get("col")),
            "end_line": _line(end.get("line")),
            "end_col": _line(end.get("col")),
            "source_snippet_included": False,
            "metavariable_values_included": False,
        }
        fingerprint = extra.get("fingerprint")
        if not isinstance(fingerprint, str) or fingerprint.strip().lower() in {
            "",
            "requires login",
        }:
            fingerprint = None
        findings.append(
            {
                "rule": check_id,
                "title": _text(extra.get("message"), check_id, 240),
                "severity": _severity(extra.get("severity"), semgrep=True),
                "confidence": 0.5,
                "evidence": evidence,
                "remediation": "Review the matched rule at the reported location and confirm the application context before remediation.",
                "external_id": _occurrence_id(
                    "semgrep-v2",
                    _identity_text(item.get("check_id"), "semgrep/unknown-rule"),
                    _identity_text(item.get("path"), "unknown"),
                    evidence["start_line"],
                    evidence["start_col"],
                    evidence["end_line"],
                    evidence["end_col"],
                    fingerprint,
                ),
            }
        )

    status = "partial" if errors else "completed"
    error = (
        f"Semgrep reported {len(errors)} error(s); coverage may be incomplete"
        if errors
        else None
    )
    coverage = {
        "objects_tested": len(scanned) if scanned else None,
        "objects_total": len(scanned) if scanned else None,
        "notes": ["Semgrep JSON parser omits source snippets and metavariable values."],
    }
    return normalize_adapter_result(
        _envelope(adapter_id, version, status, coverage, findings, error),
        asset_key=asset_key,
    )


def parse_trivy_json(
    raw: str | bytes, *, version: str, asset_key: str
) -> dict[str, Any]:
    """Parse Trivy JSON without retaining secret matches or embedded source code."""
    text = _decode(raw)
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid Trivy JSON") from exc
    if not isinstance(document, dict) or not isinstance(
        document.get("Results", []), list
    ):
        raise ValueError("invalid Trivy result object")

    results = document.get("Results", [])
    findings = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("invalid Trivy result entry")
        target = _text(result.get("Target"), "unknown", 1000)
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                raise ValueError("invalid Trivy vulnerability")
            vuln_id = _text(
                vuln.get("VulnerabilityID"), "trivy/unknown-vulnerability", 160
            )
            pkg = _text(vuln.get("PkgName"), "unknown-package", 240)
            evidence = {
                "target": target,
                "package": pkg,
                "installed_version": _text(
                    vuln.get("InstalledVersion"), "unknown", 200
                ),
                "fixed_version": _text(vuln.get("FixedVersion"), "not reported", 200),
                "class": _text(result.get("Class"), "unknown", 120),
                "type": _text(result.get("Type"), "unknown", 120),
            }
            findings.append(
                {
                    "rule": vuln_id,
                    "title": _text(vuln.get("Title"), f"{vuln_id} in {pkg}", 240),
                    "severity": _severity(vuln.get("Severity")),
                    "confidence": 0.5,
                    "evidence": evidence,
                    "remediation": (
                        "Upgrade to a fixed version after compatibility review."
                        if evidence["fixed_version"] != "not reported"
                        else "Review vendor/advisory guidance and determine an appropriate patched or mitigated version."
                    ),
                    "external_id": _occurrence_id(
                        "trivy-vuln-v2",
                        _identity_text(result.get("Target"), "unknown"),
                        _identity_text(
                            vuln.get("VulnerabilityID"), "trivy/unknown-vulnerability"
                        ),
                        _identity_text(vuln.get("PkgName"), "unknown-package"),
                        _identity_text(vuln.get("InstalledVersion"), "unknown"),
                    ),
                }
            )
        for misconfig in result.get("Misconfigurations") or []:
            if not isinstance(misconfig, dict):
                raise ValueError("invalid Trivy misconfiguration")
            rule = _text(
                misconfig.get("ID") or misconfig.get("AVDID"),
                "trivy/unknown-misconfiguration",
                160,
            )
            cause = (
                misconfig.get("CauseMetadata", {})
                if isinstance(misconfig.get("CauseMetadata"), dict)
                else {}
            )
            evidence = {
                "target": target,
                "resource": _text(cause.get("Resource"), "unknown", 500),
                "start_line": _line(cause.get("StartLine")),
                "end_line": _line(cause.get("EndLine")),
                "embedded_code_included": False,
            }
            findings.append(
                {
                    "rule": rule,
                    "title": _text(misconfig.get("Title"), rule, 240),
                    "severity": _severity(misconfig.get("Severity")),
                    "confidence": 0.5,
                    "evidence": evidence,
                    "remediation": _text(
                        misconfig.get("Resolution"),
                        "Review the configuration and apply the scanner's documented remediation guidance.",
                        1000,
                    ),
                    "external_id": _occurrence_id(
                        "trivy-config-v2",
                        _identity_text(result.get("Target"), "unknown"),
                        _identity_text(
                            misconfig.get("ID") or misconfig.get("AVDID"),
                            "trivy/unknown-misconfiguration",
                        ),
                        _identity_text(cause.get("Resource"), "unknown"),
                        evidence["start_line"],
                        evidence["end_line"],
                    ),
                }
            )
        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                raise ValueError("invalid Trivy secret finding")
            rule = _text(secret.get("RuleID"), "trivy/secret", 160)
            evidence = {
                "target": target,
                "start_line": _line(secret.get("StartLine")),
                "end_line": _line(secret.get("EndLine")),
                "secret_value_included": False,
                "embedded_code_included": False,
            }
            findings.append(
                {
                    "rule": rule,
                    "title": _text(
                        secret.get("Title"), "Potential secret detected", 240
                    ),
                    "severity": _severity(secret.get("Severity")),
                    "confidence": 0.5,
                    "evidence": evidence,
                    "remediation": "Validate the finding, rotate the affected credential if real, remove it from tracked content, and prevent recurrence.",
                    "external_id": _occurrence_id(
                        "trivy-secret-v2",
                        _identity_text(result.get("Target"), "unknown"),
                        _identity_text(secret.get("RuleID"), "trivy/secret"),
                        evidence["start_line"],
                        evidence["end_line"],
                    ),
                }
            )

    coverage = {
        "objects_tested": len(results),
        "objects_total": len(results),
        "notes": [
            "Trivy JSON parser omits secret matches and embedded source/configuration code."
        ],
    }
    return normalize_adapter_result(
        _envelope("trivy-json", version, "completed", coverage, findings),
        asset_key=asset_key,
    )


def parse_nuclei_jsonl(
    raw: str | bytes, *, version: str, asset_key: str
) -> dict[str, Any]:
    """Parse Nuclei JSONL findings while dropping requests, responses and curl commands."""
    text = _decode(raw)
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return normalize_adapter_result(
            _envelope(
                "nuclei-jsonl",
                version,
                "completed",
                {
                    "objects_tested": None,
                    "objects_total": None,
                    "notes": [
                        "Empty finding stream; Nuclei JSONL does not by itself prove target/template coverage."
                    ],
                },
                [],
            ),
            asset_key=asset_key,
        )

    findings = []
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid or truncated Nuclei JSONL") from exc
        if not isinstance(item, dict) or not isinstance(item.get("info"), dict):
            raise ValueError("invalid Nuclei finding")
        template_id = _text(item.get("template-id"), "nuclei/unknown-template", 160)
        info = item["info"]
        identity_path = _safe_url_path(
            item.get("matched-at") or item.get("url"), maximum=None
        )
        path = identity_path[:1000] if identity_path is not None else None
        evidence = {
            "template_id": template_id,
            "matcher": _text(item.get("matcher-name"), "not reported", 200),
            "protocol": _text(item.get("type"), "unknown", 80),
            "path": path,
            "raw_request_included": False,
            "raw_response_included": False,
            "curl_command_included": False,
            "extracted_values_included": False,
        }
        findings.append(
            {
                "rule": template_id,
                "title": _text(info.get("name"), template_id, 240),
                "severity": _severity(info.get("severity")),
                "confidence": 0.5,
                "evidence": evidence,
                "remediation": _text(
                    info.get("remediation"),
                    "Review the template finding, confirm it in the approved scope, and apply product-specific remediation.",
                    1000,
                ),
                "external_id": _occurrence_id(
                    "nuclei-v2",
                    _identity_text(item.get("template-id"), "nuclei/unknown-template"),
                    _identity_text(item.get("matcher-name"), "not reported"),
                    identity_path or "/",
                ),
            }
        )

    coverage = {
        "objects_tested": None,
        "objects_total": None,
        "notes": [
            "Nuclei finding JSONL does not encode complete target/template coverage; raw requests, responses, curl commands and extracted values are omitted."
        ],
    }
    return normalize_adapter_result(
        _envelope("nuclei-jsonl", version, "partial", coverage, findings),
        asset_key=asset_key,
    )


PARSERS: dict[str, Callable[..., dict[str, Any]]] = {
    "semgrep-json": parse_semgrep_json,
    "trivy-json": parse_trivy_json,
    "nuclei-jsonl": parse_nuclei_jsonl,
}


def parse_scanner_output(
    adapter_id: str, raw: str | bytes, *, version: str, asset_key: str
) -> dict[str, Any]:
    """Parse a supported scanner output format without executing the scanner."""
    parser = PARSERS.get(adapter_id)
    if parser is None:
        raise ValueError("unsupported scanner output format")
    if not isinstance(version, str) or not version.strip() or len(version) > 64:
        raise ValueError("scanner version must be a short non-empty string")
    return parser(raw, version=version.strip(), asset_key=asset_key)
