"""hackgpt_v2 optional-import helper."""

import hackgpt_v2


def test_safe_import_missing_module_returns_none():
    assert hackgpt_v2.safe_import("this_module_definitely_does_not_exist_xyz") is None


def test_safe_import_existing_module():
    assert hackgpt_v2.safe_import("json") is not None
