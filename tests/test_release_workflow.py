"""Regression tests for the release workflow's tag-creation contract."""

from pathlib import Path
import unittest


WORKFLOW = (
    Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
).read_text(encoding="utf-8")


class ReleaseWorkflowTests(unittest.TestCase):
    """Protect release tagging from GitHub App workflow-scope rejection."""

    def test_release_api_creates_the_remote_tag(self) -> None:
        """The release API must create the tag instead of a Git push."""
        self.assertNotIn("      - name: Push Release Tag\n", WORKFLOW)
        self.assertNotIn('git push origin "v$VERSION"', WORKFLOW)
        self.assertIn("          target_commitish: ${{ github.sha }}\n", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
