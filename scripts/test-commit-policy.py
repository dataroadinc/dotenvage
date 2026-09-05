"""Local hooks must reject the same invalid headers as release automation."""

from pathlib import Path
import subprocess
import tempfile
import unittest


class CommitPolicyTests(unittest.TestCase):
    def setUp(self):
        self.repository = tempfile.TemporaryDirectory()
        self.addCleanup(self.repository.cleanup)
        for arguments in [
            ["init", "--quiet"],
            ["config", "user.name", "Commit policy test"],
            ["config", "user.email", "commit-policy@example.invalid"],
        ]:
            subprocess.run(["git", "-C", self.repository.name, *arguments], check=True)

    def test_commit_header_contract(self):
        hook = Path(__file__).resolve().parents[1] / ".githooks/commit-msg"
        cases = [
            ("build(deps): update serde", True),
            ("ci(deps-dev): update action", True),
            ("feat(api)!: change contract", True),
            ("fix(api): repair\n\nBREAKING CHANGE: new wire shape", True),
            ("fix: missing scope", False),
            ("oops(api): invalid type", False),
            ("bad headline\n\nfix(api): not the headline", False),
            ("fix(api): ", False),
        ]
        for message, valid in cases:
            with self.subTest(message=message), tempfile.NamedTemporaryFile(mode="w") as source:
                source.write(message + "\n")
                source.flush()
                result = subprocess.run([str(hook), source.name], cwd=self.repository.name,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
