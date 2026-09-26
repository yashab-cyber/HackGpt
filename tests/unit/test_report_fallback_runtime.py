"""Real Jinja template behavior for the technical report fallback."""

import unittest
from unittest.mock import patch

from jinja2 import DictLoader, Environment, TemplateSyntaxError
from reporting.dynamic_reports import DynamicReportGenerator


class TechnicalReportRuntimeTests(unittest.TestCase):
    """Exercise report methods with real dependencies and no persistent services."""

    def make_generator(self, templates):
        """Avoid default DB/template directory setup while using the real class."""
        generator = DynamicReportGenerator.__new__(DynamicReportGenerator)
        generator.jinja_env = Environment(loader=DictLoader(templates))
        return generator

    def test_missing_template_returns_real_text_report(self):
        """Missing HTML must render existing text content, not a fake success."""
        generator = self.make_generator({})
        result = generator.generate_technical_report(
            {
                "target": "fixture.invalid",
                "scope": "synthetic fixture",
                "vulnerabilities": [
                    {
                        "title": "Fixture observation",
                        "severity": "low",
                        "remediation": "Fixture remediation",
                    }
                ],
            }
        )
        self.assertIn("TECHNICAL PENETRATION TEST REPORT", result)
        self.assertIn("fixture.invalid", result)
        self.assertIn("Fixture observation", result)
        self.assertIn("Fixture remediation", result)

    def test_available_template_remains_used(self):
        """The fallback must not replace a template that is actually available."""
        generator = self.make_generator(
            {"technical_report.html": "Target={{ session_data.target }}"}
        )
        with patch.object(
            generator,
            "_generate_text_technical_report",
            side_effect=AssertionError("unexpected fallback"),
        ):
            self.assertEqual(
                generator.generate_technical_report({"target": "fixture.invalid"}),
                "Target=fixture.invalid",
            )

    def test_invalid_template_is_not_silently_treated_as_missing(self):
        """Only TemplateNotFound is handled; invalid template code stays visible."""
        generator = self.make_generator({"technical_report.html": "{% invalid_tag %}"})
        with self.assertRaises(TemplateSyntaxError):
            generator.generate_technical_report({"target": "fixture.invalid"})


if __name__ == "__main__":
    unittest.main()
