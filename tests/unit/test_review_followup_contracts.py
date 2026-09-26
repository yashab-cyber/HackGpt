"""Static regression contracts for review fixes that span legacy entry points."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _function(path, name):
    """Return a named function node from a repository Python source file."""
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=str(path))
    return next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )


def test_enterprise_session_uses_database_manager_contract():
    """Keep the enterprise session flow aligned with the database manager API."""
    function = _function("hackgpt_v2.py", "run_full_enterprise_pentest")
    create_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create_pentest_session"
    ]
    assert len(create_calls) == 1
    keywords = {keyword.arg for keyword in create_calls[0].keywords}
    assert {"target", "scope", "created_by", "auth_key", "assessment_type"} <= keywords
    assert "compliance_framework" not in keywords

    update_calls = [
        node.func.attr
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.startswith("update_session")
    ]
    assert update_calls
    assert set(update_calls) == {"update_session_status"}


def test_technical_report_handles_missing_template_explicitly():
    """Require an explicit TemplateNotFound fallback to the text report."""
    function = _function("reporting/dynamic_reports.py", "generate_technical_report")
    handlers = [
        handler
        for node in ast.walk(function)
        if isinstance(node, ast.Try)
        for handler in node.handlers
    ]
    assert any(
        isinstance(handler.type, ast.Name) and handler.type.id == "TemplateNotFound"
        for handler in handlers
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_generate_text_technical_report"
        for node in ast.walk(function)
    )


def test_compliance_report_has_distinct_unmapped_count_and_list_keys():
    """Keep unmapped finding details separate from their aggregate count."""
    function = _function("security/compliance.py", "generate_compliance_report")
    dictionaries = [node for node in ast.walk(function) if isinstance(node, ast.Dict)]
    keys = []
    for dictionary in dictionaries:
        literal_keys = [
            key.value
            for key in dictionary.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        ]
        if "framework" in literal_keys and "unmapped_findings" in literal_keys:
            keys = literal_keys
            break
    assert keys
    assert len(keys) == len(set(keys))
    assert "unmapped_findings_count" in keys
    assert "unmapped_findings" in keys


def test_welcome_pr_metadata_path_never_checks_out_untrusted_code():
    """Keep the privileged fork-PR workflow metadata-only."""
    workflow = (ROOT / ".github/workflows/welcome.yml").read_text(encoding="utf-8")
    assert "pull_request_target:" in workflow
    assert "github.event_name == 'pull_request_target'" in workflow
    assert "actions/checkout" not in workflow


def test_threat_model_matches_shipped_semgrep_boundary():
    """Keep Semgrep documentation aligned with the shipped sandbox boundary."""
    threat_model = (ROOT / "workbench/THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "digest-pinned container" in threat_model
    assert chr(96) + "--pull never" + chr(96) in threat_model
    assert "network disabled" in threat_model
    assert "Executable Semgrep, Trivy" not in threat_model


def test_api_pentest_start_requires_verified_session_permission():
    """The network API must authenticate and authorize assessment creation."""
    source = (ROOT / "hackgpt_v2.py").read_text(encoding="utf-8")
    function = _function("hackgpt_v2.py", "start_pentest")
    decorators = [ast.unparse(item) for item in function.decorator_list]
    body = ast.unparse(function)
    assert "self.auth.require_auth" in decorators
    assert "self.auth.require_permission('create_session')" in decorators
    assert "request.user_id" in body
    assert '"created_by": request.user_id' in source
    assert 'route("/api/auth/login"' in source


def test_failed_phase_cannot_be_persisted_as_completed():
    """A false phase result must persist failure and return before completion."""
    source = (ROOT / "hackgpt_v2.py").read_text(encoding="utf-8")
    function = _function("hackgpt_v2.py", "run_full_enterprise_pentest")
    body = ast.unparse(function)
    assert "failed_phase" in body
    assert 'update_session_status(session_id, "failed", created_by)' in source
    failed_guard = source.index("if failed_phase is not None:")
    completed_update = source.index(
        'update_session_status(session_id, "completed", created_by)', failed_guard
    )
    failed_return = source.index("return False", failed_guard)
    assert failed_return < completed_update
