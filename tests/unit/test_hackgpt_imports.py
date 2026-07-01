"""Smoke imports for the v1 entry point (used by ci.yml)."""


def test_hackgpt_core_classes_import():
    from hackgpt import AIEngine, HackGPT, ToolManager

    assert HackGPT is not None
    assert AIEngine is not None
    assert ToolManager is not None
