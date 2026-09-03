import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / ".github" / "scripts" / "validate_skills.py"
SPEC = importlib.util.spec_from_file_location("validate_skills", VALIDATOR_PATH)
validate_skills = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validate_skills)


class ValidatorTests(unittest.TestCase):
    def tearDown(self):
        validate_skills.errors.clear()

    def test_extracts_nested_metadata_version(self):
        text = "---\nname: demo\nmetadata:\n  version: 2.3.4\n---\n"
        self.assertEqual(validate_skills.parse_metadata_version(text), "2.3.4")

    def test_only_explicit_markdown_links_count_as_bundled_references(self):
        text = (
            "See references/obsolete.md in historical prose.\n"
            "Use [the maintained guide](references/current.md).\n"
        )
        self.assertEqual(
            validate_skills.markdown_bundled_links(text),
            {"references/current.md"},
        )

    def test_backslash_bundled_link_is_detected_for_rejection(self):
        text = r"Use [bad path](references\current.md)."
        self.assertEqual(
            validate_skills.markdown_bundled_links(text),
            {r"references\current.md"},
        )

    def test_semver_validation_rejects_incomplete_version(self):
        self.assertIsNone(validate_skills.SEMVER_RE.fullmatch("1.2"))
        self.assertIsNotNone(validate_skills.SEMVER_RE.fullmatch("1.2.0"))

    def test_version_symmetry_rejects_a_marketplace_mismatch(self):
        with redirect_stdout(io.StringIO()):
            validate_skills.validate_version_symmetry(
                {"reverse-engineering": "1.2.0"},
                {"name": "reverse-engineering", "version": "1.2.0"},
                {"plugins": [{"name": "reverse-engineering", "version": "1.1.0"}]},
            )

        self.assertTrue(
            any("version mismatch" in error for error in validate_skills.errors)
        )


if __name__ == "__main__":
    unittest.main()
