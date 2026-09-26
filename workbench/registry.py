"""Closed registry for bounded workbench execution adapters.

The registry maps stable adapter IDs to reviewed constructors and request schemas. It
never accepts command strings, module paths, dynamic imports, model-selected binaries,
or arbitrary keyword forwarding. Declarations describe authority; the registry applies
an operator policy before invoking an adapter.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import Cancelled, validate_url
from .execution_contracts import ExecutionDeclaration
from .execution_receipts import EXECUTION_RECEIPT_SCHEMA, normalize_execution_receipt
from .project_adapter import ProjectMetadataAdapter, ProjectScanPolicy
from .semgrep_runner import (
    SemgrepContainerAdapter,
    SemgrepPolicy,
    semgrep_tool_public_metadata,
)
from .web_adapter import WebHeaderAdapter, WebHeaderPolicy

_ALLOWED_EFFECTS = ("read_only", "passive", "active_bounded")
_EFFECT_RANK = {name: index for index, name in enumerate(_ALLOWED_EFFECTS)}


def _safe_text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    value = value.strip()
    if (
        not value
        or len(value) > maximum
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ValueError(f"invalid {name}")
    return value


def _project_label(root: str | Path) -> str:
    raw_label = Path(root).name or "project-root"
    return (
        "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in raw_label)[:160]
        or "project-root"
    )


@dataclass(frozen=True)
class RegistryPolicy:
    """Operator-owned ceiling applied independently from adapter/model requests."""

    max_effect: str = "passive"
    allow_filesystem: bool = True
    allow_network: bool = True

    def __post_init__(self) -> None:
        if self.max_effect not in _EFFECT_RANK:
            raise ValueError("invalid maximum effect level")
        if (
            type(self.allow_filesystem) is not bool
            or type(self.allow_network) is not bool
        ):
            raise ValueError("registry authority flags must be boolean")

    def permits(self, declaration: dict[str, Any]) -> bool:
        parsed = ExecutionDeclaration.parse(declaration)
        if _EFFECT_RANK[parsed.effect_level] > _EFFECT_RANK[self.max_effect]:
            return False
        if parsed.filesystem != "none" and not self.allow_filesystem:
            return False
        if parsed.network != "none" and not self.allow_network:
            return False
        return True


class ExecutionRegistry:
    """Finite reviewed adapter registry; no dynamic extension or shell authority."""

    def __init__(self, policy: RegistryPolicy | None = None):
        self.policy = policy or RegistryPolicy()
        self._factories = {
            "native-project-metadata": self._project,
            "native-web-headers": self._web,
            "semgrep-project-local": self._semgrep,
        }

    def describe(self) -> list[dict[str, Any]]:
        declarations = [
            ProjectMetadataAdapter().execution_declaration(),
            WebHeaderAdapter().execution_declaration(),
            SemgrepContainerAdapter().execution_declaration(),
        ]
        return [
            declaration
            for declaration in declarations
            if self.policy.permits(declaration)
        ]

    def plan(self, adapter_id: str, request: Any) -> dict[str, Any]:
        """Validate typed configuration and return a sanitized, I/O-free authority preview."""
        if not isinstance(adapter_id, str) or adapter_id not in self._factories:
            raise ValueError("adapter is not in the reviewed execution registry")
        if not isinstance(request, dict):
            raise ValueError("adapter request must be an object")

        if adapter_id == "native-project-metadata":
            adapter, root = self._project_adapter(request)
            summary = {
                "adapter_id": adapter_id,
                "asset_key": request["asset_key"],
                "project_label": _project_label(root),
                "full_path_included": False,
            }
        elif adapter_id == "semgrep-project-local":
            adapter, root = self._semgrep_adapter(request)
            tool = semgrep_tool_public_metadata()
            summary = {
                "adapter_id": adapter_id,
                "asset_key": request["asset_key"],
                "project_label": _project_label(root),
                "full_path_included": False,
                "tool": tool["id"],
                "tool_version": tool["version"],
                "image_digest": tool["container"]["manifest_digest"],
                "ruleset": "repository-authored/workbench-v1",
                "container_network": "none",
                "source_mount": "read-only",
                "automatic_pull": False,
                "max_files": adapter.policy.max_files,
                "max_target_bytes": adapter.policy.max_target_bytes,
            }
        else:
            adapter = self._web_adapter(request)
            summary = {
                "adapter_id": adapter_id,
                "asset_key": request["asset_key"],
                "target": request["target"],
                "method": "HEAD",
                "redirects": False,
                "response_body": False,
            }
        declaration = adapter.execution_declaration()
        self._authorize(declaration)
        return {"declaration": declaration, "request_summary": summary}

    def execute(
        self, adapter_id: str, request: Any, *, cancel=None, web_reader=None
    ) -> dict[str, Any]:
        if not isinstance(adapter_id, str) or adapter_id not in self._factories:
            raise ValueError("adapter is not in the reviewed execution registry")
        if not isinstance(request, dict):
            raise ValueError("adapter request must be an object")
        return self._factories[adapter_id](
            request, cancel=cancel, web_reader=web_reader
        )

    def execute_with_receipt(
        self, adapter_id: str, request: Any, *, cancel=None, web_reader=None
    ) -> dict[str, Any]:
        """Execute one reviewed adapter and return budget-accounted review metadata."""
        plan = self.plan(adapter_id, request)
        if cancel is not None and cancel.is_set():
            raise InterruptedError("adapter execution cancelled before start")
        started = time.monotonic()
        result = self.execute(adapter_id, request, cancel=cancel, web_reader=web_reader)
        elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
        coverage = result.get("coverage", {}) if isinstance(result, dict) else {}
        tested = coverage.get("objects_tested")
        objects_tested = tested if type(tested) is int and tested >= 0 else 0
        network_requests = (
            1
            if adapter_id == "native-web-headers"
            and result.get("status") in {"completed", "partial"}
            else 0
        )
        return normalize_execution_receipt(
            {
                "schema": EXECUTION_RECEIPT_SCHEMA,
                "declaration": plan["declaration"],
                "request_summary": plan["request_summary"],
                "usage": {
                    "objects_tested": objects_tested,
                    "network_requests": network_requests,
                    "elapsed_ms": elapsed_ms,
                },
                "result": result,
            }
        )

    def _authorize(self, declaration: dict[str, Any]) -> None:
        if not self.policy.permits(declaration):
            raise PermissionError(
                "adapter authority exceeds the operator execution policy"
            )

    def _project_adapter(
        self, request: dict[str, Any]
    ) -> tuple[ProjectMetadataAdapter, str | Path]:
        if set(request) - {
            "root",
            "asset_key",
            "max_files",
            "max_depth",
            "timeout_seconds",
        }:
            raise ValueError("project adapter request contains unsupported fields")
        if "root" not in request or "asset_key" not in request:
            raise ValueError("project adapter requires root and asset_key")
        root = request["root"]
        if not isinstance(root, (str, Path)):
            raise ValueError("project root must be a filesystem path")
        _safe_text(request["asset_key"], "asset_key", 160)
        policy = ProjectScanPolicy(
            max_files=request.get("max_files", 1000),
            max_depth=request.get("max_depth", 12),
            timeout_seconds=request.get("timeout_seconds", 30),
        )
        adapter = ProjectMetadataAdapter(policy)
        self._authorize(adapter.execution_declaration())
        return adapter, root

    def _semgrep_adapter(
        self, request: dict[str, Any]
    ) -> tuple[SemgrepContainerAdapter, str | Path]:
        allowed = {
            "root",
            "asset_key",
            "max_files",
            "max_depth",
            "timeout_seconds",
            "max_target_bytes",
        }
        if set(request) - allowed:
            raise ValueError("Semgrep adapter request contains unsupported fields")
        if "root" not in request or "asset_key" not in request:
            raise ValueError("Semgrep adapter requires root and asset_key")
        root = request["root"]
        if not isinstance(root, (str, Path)):
            raise ValueError("Semgrep project root must be a filesystem path")
        _safe_text(request["asset_key"], "asset_key", 160)
        policy = SemgrepPolicy(
            max_files=request.get("max_files", 250),
            max_depth=request.get("max_depth", 12),
            timeout_seconds=request.get("timeout_seconds", 90),
            max_target_bytes=request.get("max_target_bytes", 500_000),
        )
        adapter = SemgrepContainerAdapter(policy)
        self._authorize(adapter.execution_declaration())
        return adapter, root

    def _web_adapter(self, request: dict[str, Any]) -> WebHeaderAdapter:
        if set(request) - {"target", "asset_key", "timeout_seconds"}:
            raise ValueError("web adapter request contains unsupported fields")
        if "target" not in request or "asset_key" not in request:
            raise ValueError("web adapter requires target and asset_key")
        _safe_text(request["target"], "target", 2048)
        _safe_text(request["asset_key"], "asset_key", 160)
        validate_url(request["target"])
        adapter = WebHeaderAdapter(
            WebHeaderPolicy(timeout_seconds=request.get("timeout_seconds", 15))
        )
        self._authorize(adapter.execution_declaration())
        return adapter

    def _project(
        self, request: dict[str, Any], *, cancel=None, web_reader=None
    ) -> dict[str, Any]:
        adapter, root = self._project_adapter(request)
        if cancel is not None and cancel.is_set():
            raise InterruptedError("adapter execution cancelled before start")
        return adapter.run(root, asset_key=request["asset_key"], cancel=cancel)

    def _semgrep(
        self, request: dict[str, Any], *, cancel=None, web_reader=None
    ) -> dict[str, Any]:
        adapter, root = self._semgrep_adapter(request)
        if cancel is not None and cancel.is_set():
            raise InterruptedError("adapter execution cancelled before start")
        return adapter.run(root, asset_key=request["asset_key"], cancel=cancel)

    def _web(
        self, request: dict[str, Any], *, cancel=None, web_reader=None
    ) -> dict[str, Any]:
        """Run the bounded web adapter and normalize engine cancellation semantics."""
        adapter = self._web_adapter(request)
        if cancel is not None and cancel.is_set():
            raise InterruptedError("adapter execution cancelled before start")
        try:
            return adapter.run(
                request["target"],
                asset_key=request["asset_key"],
                cancel=cancel,
                reader=web_reader,
            )
        except Cancelled as exc:
            raise InterruptedError("adapter execution cancelled") from exc
