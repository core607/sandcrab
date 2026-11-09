"""Exercise the contributor commands against disposable repository checkouts."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from repo_check import POINTER, anchors, check


class RepositoryChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        self.write(".gitignore", ".env\n__pycache__/\n")
        self.write("AGENTS.md", "# Rules\n\n[Review](.agents/skills/review/SKILL.md)\n")
        self.write("CLAUDE.md", POINTER)
        self.write(".agents/skills/review/SKILL.md", self.skill())
        for name in ("repo_check.py", "sync-claude-skills.py"):
            destination = self.root / "scripts" / name
            destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(Path(__file__).with_name(name), destination)
        self.assertEqual(0, self.invoke("sync-claude-skills.py").returncode)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def skill(self, description="Use to review changes."):
        return f"---\nname: review\ndescription: {description}\n---\n\n# Review\n"

    def invoke(self, name, *args):
        return subprocess.run(
            [sys.executable, "-X", "utf8", str(self.root / "scripts" / name), *args],
            cwd=self.root, text=True, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

    def assert_error(self, message):
        self.assertIn(message, "\n".join(check(self.root)))

    def test_cli_round_trip_and_read_only_drift_check(self):
        self.assertEqual(0, self.invoke("repo_check.py").returncode)
        stub = self.root / ".claude/skills/review/SKILL.md"
        previous = stub.read_bytes()
        self.write(".agents/skills/review/SKILL.md", self.skill("Use to review the changed interface."))
        failed = self.invoke("sync-claude-skills.py", "--check")
        self.assertEqual(1, failed.returncode)
        self.assertIn("stale", failed.stdout)
        self.assertEqual(previous, stub.read_bytes())
        self.assertEqual(1, self.invoke("repo_check.py").returncode)
        self.assertEqual(0, self.invoke("sync-claude-skills.py").returncode)
        self.assertEqual(0, self.invoke("repo_check.py").returncode)

    def test_invalid_source_does_not_partially_generate(self):
        self.write(".agents/skills/review/SKILL.md", self.skill("Use the revised review rules."))
        self.write(".agents/skills/broken/SKILL.md", self.skill())
        stub = self.root / ".claude/skills/review/SKILL.md"
        previous = stub.read_bytes()
        result = self.invoke("sync-claude-skills.py")
        self.assertEqual(1, result.returncode)
        self.assertIn("name must match", result.stdout)
        self.assertEqual(previous, stub.read_bytes())
        self.assertFalse((self.root / ".claude/skills/broken").exists())

    def test_frontmatter_rejects_missing_duplicate_and_unsupported_fields(self):
        for metadata in (
            "name: review", "name: review\ndescription: ",
            "name: review\ndescription: Use this.\nname: review",
            "name: review\ndescription: Use this.\nunknown: ignored",
            "name: review\ndescription: |\n  Use this.",
        ):
            with self.subTest(metadata=metadata):
                self.write(".agents/skills/review/SKILL.md", f"---\n{metadata}\n---\n")
                self.assertEqual(1, self.invoke("sync-claude-skills.py", "--check").returncode)

    def test_missing_source_file_and_inventory_fail(self):
        self.write("AGENTS.md", "# Rules\n")
        self.assert_error("skill inventory differs")
        (self.root / ".agents/skills/review/SKILL.md").unlink()
        self.assert_error("missing SKILL.md")

    def test_orphan_stub_is_reported_without_removing_user_files(self):
        self.write(".claude/skills/orphan/SKILL.md", "Retained material\n")
        self.assert_error("orphan stub")
        self.assertEqual(1, self.invoke("sync-claude-skills.py").returncode)
        self.assertEqual("Retained material\n", (self.root / ".claude/skills/orphan/SKILL.md").read_text())

    def test_links_titles_fragments_references_and_encoded_paths(self):
        self.write("docs/My guide.md", "# Guide\n\n## Read `files`\n\n## Read `files`\n")
        self.write("README.md", '\n'.join((
            '[Guide](<docs/My guide.md> "Guide title")',
            '[Details](docs/My%20guide.md#read-files-1)',
            '[Link][guide]', '[Guide][]', '[Guide]: docs/My%20guide.md#guide',
            '[Remote](https://example.invalid/path)', '[Mail](mailto:test@example.invalid)',
        )))
        self.assertEqual([], check(self.root))
        self.write("README.md", "[Broken](docs/My%20guide.md#missing)\n")
        self.assert_error("missing heading")

    def test_heading_slugs_match_formatted_titles_and_duplicates(self):
        self.assertEqual({"read-the-api", "read-the-api-1"}, anchors(
            "# Read the [`API`](api.json)\n\n## Read the API\n"
        ))

    def test_broken_local_and_reference_links_fail(self):
        for link in ("[Missing](missing.md)", "[Missing]: missing.md", "![Image](missing.png)"):
            with self.subTest(link=link):
                self.write("README.md", link)
                self.assert_error("missing local target")
        self.write("README.md", "[Missing][undefined]\n")
        self.assert_error("undefined link reference")

    def test_code_examples_and_frozen_history_do_not_require_live_targets(self):
        self.write("README.md", '\n'.join((
            "`[Example](missing.md)`", "```md", "[Example](missing.md)", "```",
            "~~~~md", "[Example](missing.md)", "~~~~",
        )))
        self.write("notes/archived/2020-01-01-old.md", "[Historical](missing.md)\n")
        self.assertEqual([], check(self.root))

    def test_deleted_tracked_target_is_not_treated_as_present(self):
        self.write("README.md", "[Helper](helper.py)\n")
        self.write("helper.py", "# helper\n")
        subprocess.run(["git", "add", "helper.py"], cwd=self.root, check=True)
        self.assertEqual([], check(self.root))
        (self.root / "helper.py").unlink()
        self.assert_error("missing local target")

    def test_escape_and_uncommitted_generated_targets_fail(self):
        self.write("README.md", "[Outside](../outside.md)\n")
        self.assert_error("link leaves repository")
        self.write(".gitignore", ".env\n/generated/\n")
        self.write("generated/guide.md", "# Generated\n")
        self.write("README.md", "[Generated](generated/guide.md)\n")
        self.assert_error("missing local target")

    def test_pointer_and_credential_ignore_have_one_owner(self):
        self.write("CLAUDE.md", POINTER + "Different instructions.\n")
        self.assert_error("keep only the AGENTS.md pointer")
        self.write(".gitignore", "target/\n.env\n")
        self.assert_error("first line must be .env")


if __name__ == "__main__":
    unittest.main()
