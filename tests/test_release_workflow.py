"""Regression tests for the single tested-revision release contract."""

from pathlib import Path
import unittest


WORKFLOW = (
    Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
).read_text(encoding="utf-8")


class ReleaseWorkflowTests(unittest.TestCase):
    """Keep publishing and validation attached to one immutable revision."""

    def test_tag_and_release_use_the_prepared_revision(self) -> None:
        """The triggering SHA is not the generated and validated version commit."""
        self.assertNotIn("      - name: Push Release Tag\n", WORKFLOW)
        self.assertIn("legra-ai/github-actions/.github/actions/tag-tested-release@main", WORKFLOW)
        self.assertNotIn("target_commitish: ${{ github.sha }}", WORKFLOW)
        self.assertIn("target_commitish: ${{ needs.version-check.outputs.revision }}", WORKFLOW)

    def test_old_parallel_publish_workflows_are_removed(self) -> None:
        workflows = Path(__file__).parents[1] / ".github/workflows"
        for name in ["auto-version-bump.yml", "dependabot-auto-merge.yml",
                     "dependabot-approve.yml", "dependabot-automerge.yml"]:
            self.assertFalse((workflows / name).exists(), name)

    def test_release_remains_draft_until_all_registries_finish(self) -> None:
        self.assertIn("draft: true", WORKFLOW)
        self.assertLess(WORKFLOW.index("name: Publish to PyPI"),
                        WORKFLOW.index("name: Complete release after all registries succeed"))

    def test_workflow_contract_tests_run_in_ci(self) -> None:
        self.assertIn("python3 -m unittest discover -s tests -p test_release_workflow.py", WORKFLOW)

    def test_ci_and_hooks_use_the_same_pinned_formatter(self) -> None:
        root = Path(__file__).parents[1]
        self.assertRegex((root / "rustfmt-toolchain").read_text().strip(),
                         r"^nightly-\d{4}-\d{2}-\d{2}$")
        self.assertIn("./scripts/fmt.sh --check", WORKFLOW)
        self.assertIn("./scripts/fmt.sh --check", (root / ".githooks/pre-commit").read_text())
        self.assertIn("toolchain: ${{ steps.formatter.outputs.toolchain }}", WORKFLOW)
        self.assertNotIn("cargo +nightly", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
