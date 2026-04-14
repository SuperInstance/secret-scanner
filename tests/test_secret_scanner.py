"""Tests for the Fleet Secret Scanner.

Covers pattern matching, file scanning, git history scanning,
diff scanning, baseline management, reporter output, CLI args, and allow-lists.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure the secret-scanner package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import (
    FleetSecretScanner,
    ScanResult,
    SecretMatch,
    Severity,
    SECRET_PATTERNS,
)
from reporter import ScanReporter
from git_analyzer import GitAnalyzer, CommitInfo
from cli import build_parser, main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _TempRepoMixin:
    """Mixin providing a temp git repo that can be created per-test."""

    def _make_temp_repo(self) -> Path:
        """Create a temporary git repo and return its path."""
        tmpdir = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init"], cwd=str(tmpdir), capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "scanner@test.com"],
            cwd=str(tmpdir), capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test Scanner"],
            cwd=str(tmpdir), capture_output=True,
        )
        self.addCleanup(lambda: _rmtree(tmpdir))
        return tmpdir

    def _commit_file(self, repo: Path, name: str, content: str, message: str = "add file") -> str:
        """Write a file and commit it. Returns the commit hash."""
        (repo / name).write_text(content)
        subprocess.run(["git", "-C", str(repo), "add", name], capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", message],
            capture_output=True,
        )
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        )
        return result.stdout.strip()


def _rmtree(p: Path) -> None:
    """Recursively remove a directory tree."""
    if p.exists():
        for child in p.iterdir():
            if child.is_dir():
                _rmtree(child)
            else:
                child.unlink()
        p.rmdir()


# ---------------------------------------------------------------------------
# 1. Pattern matching tests
# ---------------------------------------------------------------------------

class TestSecretPatterns(unittest.TestCase):
    """Test that all secret types are correctly detected."""

    def _assert_detects(self, line: str, expected_type: str) -> None:
        """Assert that a line containing a secret is detected."""
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(line, "test.py")
        types = {m.secret_type for m in matches}
        self.assertIn(expected_type, types,
                      f"Expected '{expected_type}' in {types} for line: {line}")

    def _assert_no_detect(self, line: str) -> None:
        """Assert that a line does NOT trigger a secret match."""
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(line, "test.py")
        # Allow-list patterns in test files should be skipped
        self.assertEqual(len(matches), 0,
                         f"Unexpected matches for line: {line}")

    # --- GitHub PATs ---
    def test_github_pat_fine_grained(self):
        self._assert_detects(
            "token = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
            "GitHub Personal Access Token",
        )

    def test_github_oauth(self):
        self._assert_detects(
            "GITHUB_TOKEN=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
            "GitHub Personal Access Token",
        )

    # --- AWS Keys ---
    def test_aws_access_key(self):
        self._assert_detects(
            "aws_access_key = AKIAIOSFODNN7ABCDEFGH",
            "AWS Access Key ID",
        )

    def test_aws_secret_key(self):
        self._assert_detects(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYABCDEFGH1234567",
            "AWS Secret Access Key",
        )

    # --- Private Keys ---
    def test_rsa_private_key(self):
        self._assert_detects(
            "-----BEGIN RSA PRIVATE KEY-----",
            "Private Key",
        )

    def test_ec_private_key(self):
        self._assert_detects(
            "-----BEGIN EC PRIVATE KEY-----",
            "Private Key",
        )

    def test_generic_private_key(self):
        self._assert_detects(
            "-----BEGIN PRIVATE KEY-----",
            "Private Key",
        )

    # --- Connection Strings ---
    def test_postgres_connection(self):
        self._assert_detects(
            "DATABASE_URL=postgresql://user:pass@db.prod.com:5432/mydb",
            "Database Connection String",
        )

    def test_mongodb_connection(self):
        self._assert_detects(
            "MONGO_URI=mongodb+srv://user:pass@cluster.prod.com/mydb",
            "Database Connection String",
        )

    def test_mysql_connection(self):
        self._assert_detects(
            "DB=mysql://root:secret@db.prod.com:3306/app",
            "Database Connection String",
        )

    # --- JWTs ---
    def test_jwt_token(self):
        self._assert_detects(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "JSON Web Token",
        )

    # --- Slack Tokens ---
    def test_slack_bot_token(self):
        self._assert_detects(
            f"SLACK_TOKEN={'xoxb-' + '123456789012' + '-ABCDEFGHIJKLMNOPQRSTUVWXYZabcd'}",
            "Slack Token",
        )

    # --- Stripe Keys ---
    def test_stripe_live_key(self):
        self._assert_detects(
            f"STRIPE_KEY={'sk_live_' + 'ABCDEFGHIJKLMNOPQRSTUVWX' + 'abcdefghijklmnop'}",
            "Stripe Live Key",
        )

    def test_stripe_test_key(self):
        self._assert_detects(
            f"STRIPE_KEY={'pk_live_' + 'ABCDEFGHIJKLMNOPQRSTUVWX' + 'abcdefghijklmnop'}",
            "Stripe Live Key",
        )

    # --- Google API Keys ---
    def test_google_api_key(self):
        self._assert_detects(
            "GOOGLE_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuvwx",
            "Google API Key",
        )

    # --- Hardcoded Passwords ---
    def test_hardcoded_password(self):
        self._assert_detects(
            'db_password = "super_secret_password_123"',
            "Hardcoded Password",
        )

    # --- Generic API Key ---
    def test_generic_api_key(self):
        self._assert_detects(
            'api_key = "ABCDEFGH12345678abcdefgh12"',
            "Generic API Key",
        )

    # --- False positives ---
    def test_false_positive_placeholder(self):
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(
            "API_KEY=REPLACE_WITH_YOUR_KEY", "config.py",
        )
        self.assertEqual(len(matches), 0)

    def test_false_positive_env_var_ref(self):
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(
            'password = "${DATABASE_PASSWORD}"', "settings.py",
        )
        # The ${} reference itself should be filtered, but the surrounding
        # "password =" line could still match Hardcoded Password pattern.
        # We check that at minimum the env var ref value is not reported.
        for m in matches:
            self.assertNotEqual(m.matched_value, "${DATABASE_PASSWORD}")

    def test_false_positive_localhost(self):
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(
            "DB=mysql://root@localhost:3306/app", "settings.py",
        )
        self.assertEqual(len(matches), 0)

    def test_false_positive_sqlite(self):
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(
            "DB=sqlite:///./dev.db", "settings.py",
        )
        self.assertEqual(len(matches), 0)


# ---------------------------------------------------------------------------
# 2. File scanning tests
# ---------------------------------------------------------------------------

class TestFileScanning(_TempRepoMixin, unittest.TestCase):
    """Test scanning individual files and directories."""

    def test_scan_file_with_secret(self):
        """A file containing a real secret should be detected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7ABCDEFGH"\n')
            f.flush()
            path = f.name
        self.addCleanup(os.unlink, path)

        scanner = FleetSecretScanner()
        result = scanner.scan_file(path)
        self.assertTrue(result.has_secrets)
        self.assertEqual(len(result.matches), 1)
        self.assertEqual(result.matches[0].secret_type, "AWS Access Key ID")

    def test_scan_clean_file(self):
        """A file without secrets should report clean."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('print("Hello, world!")\n')
            f.flush()
            path = f.name
        self.addCleanup(os.unlink, path)

        scanner = FleetSecretScanner()
        result = scanner.scan_file(path)
        self.assertFalse(result.has_secrets)

    def test_scan_nonexistent_file(self):
        """Scanning a nonexistent file should return an error."""
        scanner = FleetSecretScanner()
        result = scanner.scan_file("/tmp/nonexistent_file_12345.py")
        self.assertIsNotNone(result.error)
        self.assertFalse(result.has_secrets)

    def test_scan_directory_instead_of_file(self):
        """Scanning a directory as a file should return an error."""
        scanner = FleetSecretScanner()
        result = scanner.scan_file("/tmp")
        self.assertIsNotNone(result.error)

    def test_scan_repo_with_secrets(self):
        """A repo with secret files should be detected."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "config.py", 'AWS_KEY = "AKIAIOSFODNN7ABCDEFGH"\n')

        scanner = FleetSecretScanner()
        result = scanner.scan_repo(repo)
        self.assertTrue(result.has_secrets)
        self.assertGreater(result.files_scanned, 0)

    def test_scan_clean_repo(self):
        """A repo without secrets should be clean."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "main.py", 'print("Hello!")\n')

        scanner = FleetSecretScanner()
        result = scanner.scan_repo(repo)
        self.assertFalse(result.has_secrets)

    def test_ignored_directories(self):
        """node_modules and .git should be skipped."""
        repo = self._make_temp_repo()
        # Create node_modules with a fake secret
        nm = repo / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('var key = "AKIAIOSFODNN7ABCDEFGH";\n')
        self._commit_file(repo, "main.py", 'print("Hello!")\n')

        scanner = FleetSecretScanner()
        result = scanner.scan_repo(repo)
        # Should NOT detect the secret in node_modules
        for m in result.matches:
            self.assertNotIn("node_modules", m.file_path)


# ---------------------------------------------------------------------------
# 3. Git history scanning tests
# ---------------------------------------------------------------------------

class TestGitHistoryScanning(_TempRepoMixin, unittest.TestCase):
    """Test scanning git history for secrets."""

    def test_secret_in_commit_history(self):
        """A secret committed then removed should still be found in history."""
        repo = self._make_temp_repo()

        # Commit 1: Add a file with a secret
        self._commit_file(
            repo, "secrets.py",
            'AWS_KEY = "AKIAIOSFODNN7ABCDEFGH"\nprint(AWS_KEY)\n',
            "add secrets file",
        )

        # Commit 2: Remove the secret
        (repo / "secrets.py").write_text('print("no secret here")\n')
        subprocess.run(["git", "-C", str(repo), "add", "secrets.py"], capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", "remove secret"],
            capture_output=True,
        )

        scanner = FleetSecretScanner()
        result = scanner.scan_repo(repo)

        # Secret should still be found in git history
        self.assertTrue(result.has_secrets)
        history_matches = [m for m in result.matches if m.commit_hash]
        self.assertGreater(len(history_matches), 0,
                           "Secret should be found in git history")

    def test_scan_specific_commit(self):
        """Scanning a specific commit should find its secrets."""
        repo = self._make_temp_repo()
        commit_hash = self._commit_file(
            repo, "config.py",
            'AWS_KEY = "AKIAIOSFODNN7ABCDEFGH"\n',
            "add config with aws key",
        )

        scanner = FleetSecretScanner()
        result = scanner.scan_commit(repo, commit_hash)
        self.assertTrue(result.has_secrets)

    def test_scan_clean_commit(self):
        """A commit without secrets should be clean."""
        repo = self._make_temp_repo()
        commit_hash = self._commit_file(
            repo, "app.py",
            'def hello(): return "world"\n',
            "add app",
        )

        scanner = FleetSecretScanner()
        result = scanner.scan_commit(repo, commit_hash)
        self.assertFalse(result.has_secrets)


# ---------------------------------------------------------------------------
# 4. Diff scanning tests
# ---------------------------------------------------------------------------

class TestDiffScanning(_TempRepoMixin, unittest.TestCase):
    """Test scanning uncommitted and staged changes."""

    def test_scan_uncommitted_diff(self):
        """Uncommitted changes with secrets should be detected."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "main.py", 'print("hello")\n', "initial")

        # Make uncommitted change with a secret
        (repo / "main.py").write_text(
            'GITHUB_TOKEN="ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"\nprint("hello")\n'
        )

        scanner = FleetSecretScanner()
        result = scanner.scan_diff(repo)
        self.assertTrue(result.has_secrets)
        self.assertEqual(result.scan_mode, "diff")

    def test_scan_staged_changes(self):
        """Staged changes with secrets should be detected."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "main.py", 'print("hello")\n', "initial")

        # Stage a new file with a secret
        (repo / "staged.py").write_text(f'SLACK_TOKEN="{chr(120)}oxb-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"\n')
        subprocess.run(["git", "-C", str(repo), "add", "staged.py"], capture_output=True)

        scanner = FleetSecretScanner()
        result = scanner.scan_staged(repo)
        self.assertTrue(result.has_secrets)
        self.assertEqual(result.scan_mode, "staged")

    def test_clean_diff(self):
        """No diff should produce clean result."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "main.py", 'print("hello")\n', "initial")

        scanner = FleetSecretScanner()
        result = scanner.scan_diff(repo)
        self.assertFalse(result.has_secrets)


# ---------------------------------------------------------------------------
# 5. Baseline tests
# ---------------------------------------------------------------------------

class TestBaseline(_TempRepoMixin, unittest.TestCase):
    """Test baseline save/compare functionality."""

    def test_save_and_load_baseline(self):
        """Saved baseline should be loadable."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "app.py", 'AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n', "initial")

        scanner = FleetSecretScanner()
        result = scanner.scan_repo(repo)
        baseline_path = scanner.save_baseline(repo, result)

        self.assertTrue(baseline_path.exists())

        loaded = FleetSecretScanner.load_baseline(baseline_path)
        self.assertEqual(len(loaded["fingerprints"]), len(result.matches))
        self.assertIn("timestamp", loaded)
        self.assertIn("summary", loaded)

    def test_baseline_no_drift(self):
        """Comparing with same state should show no drift."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "app.py", 'AWS_KEY="AKIAIOSFODNN7ABCDEFGH"\n', "initial")

        scanner = FleetSecretScanner()
        result1 = scanner.scan_repo(repo)
        baseline_path = scanner.save_baseline(repo, result1)

        # Re-scan (no changes)
        result2 = scanner.scan_repo(repo)
        comparison = FleetSecretScanner.compare_baseline(
            FleetSecretScanner.load_baseline(baseline_path), result2,
        )
        self.assertFalse(comparison["drift_detected"])
        self.assertEqual(comparison["new_count"], 0)

    def test_baseline_detects_new_secret(self):
        """Adding a new secret should be detected as drift."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "app.py", 'print("clean")\n', "initial")

        scanner = FleetSecretScanner()
        result1 = scanner.scan_repo(repo)
        baseline_path = scanner.save_baseline(repo, result1)

        # Add a new secret
        self._commit_file(
            repo, "config.py",
            'DB_PASS="super_secret_password_123"\n',
            "add config",
        )

        result2 = scanner.scan_repo(repo)
        comparison = FleetSecretScanner.compare_baseline(
            FleetSecretScanner.load_baseline(baseline_path), result2,
        )
        self.assertTrue(comparison["drift_detected"])
        self.assertGreater(comparison["new_count"], 0)

    def test_baseline_file_not_found(self):
        """Loading a nonexistent baseline should raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            FleetSecretScanner.load_baseline("/tmp/nonexistent_baseline.json")

    def test_baseline_custom_path(self):
        """Baseline can be saved to a custom path."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "app.py", 'print("clean")\n', "initial")

        scanner = FleetSecretScanner()
        result = scanner.scan_repo(repo)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            custom_path = f.name
        self.addCleanup(os.unlink, custom_path)

        saved = scanner.save_baseline(repo, result, custom_path)
        self.assertEqual(str(saved), custom_path)
        self.assertTrue(Path(custom_path).exists())


# ---------------------------------------------------------------------------
# 6. Reporter output tests
# ---------------------------------------------------------------------------

class TestReporter(_TempRepoMixin, unittest.TestCase):
    """Test reporter output formats."""

    def _make_result_with_secrets(self) -> ScanResult:
        """Create a ScanResult with some test matches."""
        result = ScanResult(
            repo_path="/tmp/test-repo",
            scan_mode="test",
            files_scanned=3,
            files_skipped=1,
        )
        result.matches = [
            SecretMatch(
                file_path="config.py",
                line_number=10,
                line_content='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
                secret_type="AWS Access Key ID",
                severity=Severity.CRITICAL,
                matched_value="AKIAIOSFODNN7EXAMPLE",
                commit_hash="abc123",
                commit_message="add aws key",
            ),
            SecretMatch(
                file_path="app.py",
                line_number=25,
                line_content="password = 'hunter2'",
                secret_type="Hardcoded Password",
                severity=Severity.HIGH,
                matched_value="'hunter2'",
            ),
        ]
        return result

    def test_json_report(self):
        """JSON report should be valid JSON with expected structure."""
        result = self._make_result_with_secrets()
        reporter = ScanReporter(result)
        output = reporter.to_json()

        data = json.loads(output)
        self.assertEqual(data["report_version"], "1.0")
        self.assertEqual(data["total_secrets"], 2)
        self.assertTrue(data["has_secrets"])
        self.assertIn("generated_at", data)
        self.assertEqual(len(data["matches"]), 2)
        self.assertIn("severity_counts", data)

    def test_text_report(self):
        """Text report should be human-readable."""
        result = self._make_result_with_secrets()
        reporter = ScanReporter(result)
        output = reporter.to_text()

        self.assertIn("FLEET SECRET SCAN REPORT", output)
        self.assertIn("CRITICAL", output)
        self.assertIn("HIGH", output)
        self.assertIn("config.py", output)
        self.assertIn("app.py", output)
        self.assertIn("secret(s) found", output)

    def test_text_report_clean(self):
        """Clean report should say no secrets found."""
        result = ScanResult(repo_path="/tmp/clean", scan_mode="test", files_scanned=10)
        reporter = ScanReporter(result)
        output = reporter.to_text()

        self.assertIn("No secrets found", output)

    def test_markdown_report(self):
        """Markdown report should have proper headers and tables."""
        result = self._make_result_with_secrets()
        reporter = ScanReporter(result)
        output = reporter.to_markdown()

        self.assertIn("# Fleet Secret Scan Report", output)
        self.assertIn("##", output)  # Sections
        self.assertIn("|", output)    # Tables
        self.assertIn("config.py", output)

    def test_diff_report(self):
        """Diff report should show drift information."""
        result = self._make_result_with_secrets()
        baseline = {
            "timestamp": "2025-01-01T00:00:00Z",
            "fingerprints": [],
            "summary": {},
        }

        output = ScanReporter.diff_report(baseline, result)
        self.assertIn("BASELINE DRIFT REPORT", output)
        self.assertIn("DRIFT DETECTED", output)
        self.assertIn("New Secrets", output)

    def test_diff_report_markdown(self):
        """Markdown diff report should have proper table formatting."""
        result = self._make_result_with_secrets()
        baseline = {
            "timestamp": "2025-01-01T00:00:00Z",
            "fingerprints": [],
            "summary": {},
        }

        output = ScanReporter.diff_report_markdown(baseline, result)
        self.assertIn("# Baseline Drift Report", output)
        self.assertIn("|", output)

    def test_save_report(self):
        """Report should be saveable to a file."""
        result = self._make_result_with_secrets()
        reporter = ScanReporter(result)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name
        self.addCleanup(os.unlink, output_path)

        saved = reporter.save(output_path, "json")
        self.assertEqual(str(saved), output_path)
        self.assertTrue(Path(output_path).exists())

        data = json.loads(Path(output_path).read_text())
        self.assertEqual(data["total_secrets"], 2)

    def test_save_invalid_format(self):
        """Saving with invalid format should raise ValueError."""
        result = self._make_result_with_secrets()
        reporter = ScanReporter(result)

        with self.assertRaises(ValueError):
            reporter.save("/tmp/test.xml", "xml")


# ---------------------------------------------------------------------------
# 7. CLI argument tests
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):
    """Test CLI argument parsing."""

    def test_scan_command(self):
        """scan command should parse repo_path."""
        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp/my-repo"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.repo_path, "/tmp/my-repo")
        self.assertEqual(args.format, "text")

    def test_scan_with_json_format(self):
        """scan --format json should set format."""
        parser = build_parser()
        args = parser.parse_args(["scan", "--format", "json", "/tmp/repo"])
        self.assertEqual(args.format, "json")

    def test_scan_all_command(self):
        """scan-all should parse fleet-dir option."""
        parser = build_parser()
        args = parser.parse_args(["scan-all", "--fleet-dir", "/repos"])
        self.assertEqual(args.command, "scan-all")
        self.assertEqual(args.fleet_dir, "/repos")

    def test_scan_diff_command(self):
        """scan-diff should parse repo_path."""
        parser = build_parser()
        args = parser.parse_args(["scan-diff", "/tmp/repo"])
        self.assertEqual(args.command, "scan-diff")

    def test_scan_staged_command(self):
        """scan-staged should parse repo_path."""
        parser = build_parser()
        args = parser.parse_args(["scan-staged", "/tmp/repo"])
        self.assertEqual(args.command, "scan-staged")

    def test_scan_file_command(self):
        """scan-file should parse file_path."""
        parser = build_parser()
        args = parser.parse_args(["scan-file", "/tmp/config.py"])
        self.assertEqual(args.command, "scan-file")
        self.assertEqual(args.file_path, "/tmp/config.py")

    def test_baseline_save_command(self):
        """baseline save should parse repo_path and output."""
        parser = build_parser()
        args = parser.parse_args(["baseline", "save", "/tmp/repo", "--output", "/tmp/bl.json"])
        self.assertEqual(args.command, "baseline")
        self.assertEqual(args.baseline_command, "save")
        self.assertEqual(args.repo_path, "/tmp/repo")
        self.assertEqual(args.output, "/tmp/bl.json")

    def test_baseline_compare_command(self):
        """baseline compare should parse repo_path and baseline."""
        parser = build_parser()
        args = parser.parse_args([
            "baseline", "compare", "/tmp/repo", "--baseline", "/tmp/bl.json",
        ])
        self.assertEqual(args.command, "baseline")
        self.assertEqual(args.baseline_command, "compare")
        self.assertEqual(args.baseline, "/tmp/bl.json")

    def test_onboard_command(self):
        """onboard should parse without arguments."""
        parser = build_parser()
        args = parser.parse_args(["onboard"])
        self.assertEqual(args.command, "onboard")

    def test_no_command_returns_zero(self):
        """No command should print help and return 0."""
        ret = main([])
        self.assertEqual(ret, 0)

    def test_markdown_format_flag(self):
        """-f markdown should work."""
        parser = build_parser()
        args = parser.parse_args(["scan", "-f", "markdown", "/tmp/repo"])
        self.assertEqual(args.format, "markdown")


# ---------------------------------------------------------------------------
# 8. Allow-list tests
# ---------------------------------------------------------------------------

class TestAllowList(_TempRepoMixin, unittest.TestCase):
    """Test that allow-list correctly skips test fixtures and docs."""

    def test_test_files_allowed(self):
        """Secrets in test files should be skipped."""
        scanner = FleetSecretScanner()
        # File path matches test pattern
        self.assertTrue(scanner.is_allowed("tests/test_config.py"))
        self.assertTrue(scanner.is_allowed("spec/app_spec.rb"))
        self.assertTrue(scanner.is_allowed("__tests__/utils.test.ts"))

    def test_fixture_files_allowed(self):
        """Secrets in fixture files should be skipped."""
        scanner = FleetSecretScanner()
        self.assertTrue(scanner.is_allowed("fixtures/aws_credentials.json"))
        self.assertTrue(scanner.is_allowed("test_fixtures/secrets.env"))
        self.assertTrue(scanner.is_allowed("mocks/github_token.txt"))

    def test_normal_files_not_allowed(self):
        """Regular source files should NOT be allowed."""
        scanner = FleetSecretScanner()
        self.assertFalse(scanner.is_allowed("src/config.py"))
        self.assertFalse(scanner.is_allowed("app/settings.py"))
        self.assertFalse(scanner.is_allowed("lib/database.py"))

    def test_docs_files_allowed(self):
        """Documentation files should be allowed."""
        scanner = FleetSecretScanner()
        self.assertTrue(scanner.is_allowed("README.md"))
        self.assertTrue(scanner.is_allowed("docs/setup.md"))
        self.assertTrue(scanner.is_allowed("CONTRIBUTING.rst"))

    def test_scan_test_file_skipped(self):
        """Scanning should skip files that match allow-list."""
        repo = self._make_temp_repo()

        # Create a test file with a fake secret
        test_dir = repo / "tests"
        test_dir.mkdir()
        self._commit_file(
            repo, "tests/test_aws.py",
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
            "add test",
        )

        scanner = FleetSecretScanner()
        result = scanner.scan_repo(repo)

        # Test file secrets should be skipped
        test_matches = [m for m in result.matches if "tests/" in m.file_path]
        self.assertEqual(len(test_matches), 0,
                         "Secrets in test files should be allow-listed")

    def test_example_dir_allowed(self):
        """Secrets in example directories should be skipped."""
        scanner = FleetSecretScanner()
        self.assertTrue(scanner.is_allowed("examples/config.py"))
        self.assertTrue(scanner.is_allowed("example-app/settings.py"))


# ---------------------------------------------------------------------------
# 9. Git Analyzer tests
# ---------------------------------------------------------------------------

class TestGitAnalyzer(_TempRepoMixin, unittest.TestCase):
    """Test git analyzer functionality."""

    def test_get_all_commits(self):
        """Should return list of commits."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "a.py", "a=1\n", "first")
        self._commit_file(repo, "b.py", "b=2\n", "second")

        analyzer = GitAnalyzer()
        commits = analyzer.get_all_commits(repo)
        self.assertEqual(len(commits), 2)
        self.assertEqual(commits[0].subject, "second")
        self.assertEqual(commits[1].subject, "first")

    def test_get_commit_diff(self):
        """Should return diff text for a commit."""
        repo = self._make_temp_repo()
        commit_hash = self._commit_file(
            repo, "config.py", 'KEY="value"\n', "add config",
        )

        analyzer = GitAnalyzer()
        diff = analyzer.get_commit_diff(repo, commit_hash)
        self.assertIn("KEY", diff)

    def test_get_file_at_commit(self):
        """Should return file contents at a specific commit."""
        repo = self._make_temp_repo()
        commit_hash = self._commit_file(
            repo, "app.py", 'print("hello")\n', "initial",
        )

        analyzer = GitAnalyzer()
        content = analyzer.get_file_at_commit(repo, commit_hash, "app.py")
        self.assertIn("hello", content)

    def test_find_secret_introducing_commits(self):
        """Should find commits that introduced secrets."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "clean.py", "x=1\n", "clean commit")
        self._commit_file(
            repo, "secrets.py",
            'AWS_KEY="AKIAIOSFODNN7ABCDEFGH"\n',
            "add aws key",
        )

        analyzer = GitAnalyzer()
        secret_commits = analyzer.find_secret_introducing_commits(repo)
        self.assertGreater(len(secret_commits), 0)

        # The secret-introducing commit should be found
        found_subjects = {sc.commit.subject for sc in secret_commits}
        self.assertIn("add aws key", found_subjects)

    def test_repo_summary(self):
        """Should return repository summary."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "app.py", "x=1\n", "initial")

        analyzer = GitAnalyzer()
        summary = analyzer.repo_summary(repo)

        self.assertEqual(summary["total_commits"], 1)
        self.assertIn("branch", summary)
        self.assertIn("latest_commit", summary)

    def test_save_and_check_baseline_drift(self):
        """Baseline drift check via GitAnalyzer should work."""
        repo = self._make_temp_repo()
        self._commit_file(repo, "app.py", "x=1\n", "initial")

        scanner = FleetSecretScanner()
        analyzer = GitAnalyzer(scanner)

        # Save baseline
        result = scanner.scan_repo(repo)
        baseline_path = analyzer.save_current_baseline(repo, result)

        # No drift yet
        result2 = scanner.scan_repo(repo)
        comparison = analyzer.check_baseline_drift(baseline_path, result2)
        self.assertFalse(comparison["drift_detected"])

        # Add a secret — drift detected
        self._commit_file(
            repo, "config.py",
            'DB_PASS="super_secret_password_123"\n',
            "add password",
        )
        result3 = scanner.scan_repo(repo)
        comparison = analyzer.check_baseline_drift(baseline_path, result3)
        self.assertTrue(comparison["drift_detected"])


# ---------------------------------------------------------------------------
# 10. Severity and data model tests
# ---------------------------------------------------------------------------

class TestSeverityAndModels(unittest.TestCase):
    """Test severity ordering, secret match fingerprinting, and scan result."""

    def test_severity_values(self):
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.LOW.value, "LOW")

    def test_fingerprint_stability(self):
        """Same match should produce same fingerprint."""
        m1 = SecretMatch(
            file_path="a.py", line_number=5,
            line_content="key", secret_type="AWS",
            severity=Severity.CRITICAL, matched_value="AKIA1234",
        )
        m2 = SecretMatch(
            file_path="a.py", line_number=5,
            line_content="key", secret_type="AWS",
            severity=Severity.CRITICAL, matched_value="AKIA1234",
        )
        self.assertEqual(m1.fingerprint(), m2.fingerprint())

    def test_fingerprint_uniqueness(self):
        """Different matches should produce different fingerprints."""
        m1 = SecretMatch(
            file_path="a.py", line_number=5,
            line_content="key", secret_type="AWS",
            severity=Severity.CRITICAL, matched_value="AKIA1234",
        )
        m2 = SecretMatch(
            file_path="b.py", line_number=5,
            line_content="key", secret_type="AWS",
            severity=Severity.CRITICAL, matched_value="AKIA1234",
        )
        self.assertNotEqual(m1.fingerprint(), m2.fingerprint())

    def test_secret_match_to_dict(self):
        """SecretMatch.to_dict() should contain expected fields."""
        m = SecretMatch(
            file_path="config.py", line_number=10,
            line_content='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
            secret_type="AWS Access Key ID",
            severity=Severity.CRITICAL,
            matched_value="AKIAIOSFODNN7EXAMPLE",
            commit_hash="abc123",
        )
        d = m.to_dict()
        self.assertEqual(d["file_path"], "config.py")
        self.assertEqual(d["line_number"], 10)
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["secret_type"], "AWS Access Key ID")
        self.assertIn("fingerprint", d)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", d["matched_value"])  # redacted

    def test_scan_result_severity_counts(self):
        """ScanResult should aggregate severity counts."""
        result = ScanResult(repo_path="/tmp", scan_mode="test")
        result.matches = [
            SecretMatch("a.py", 1, "", "AWS", Severity.CRITICAL, "AKIA"),
            SecretMatch("a.py", 2, "", "AWS", Severity.CRITICAL, "AKIA2"),
            SecretMatch("b.py", 3, "", "Pass", Severity.HIGH, "pw"),
            SecretMatch("c.py", 4, "", "Token", Severity.MEDIUM, "tk"),
        ]
        counts = result.severity_counts()
        self.assertEqual(counts["CRITICAL"], 2)
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(counts["MEDIUM"], 1)

    def test_scan_result_matches_by_file(self):
        """ScanResult should group matches by file."""
        result = ScanResult(repo_path="/tmp", scan_mode="test")
        result.matches = [
            SecretMatch("a.py", 1, "", "AWS", Severity.CRITICAL, "AKIA"),
            SecretMatch("a.py", 2, "", "AWS", Severity.CRITICAL, "AKIA2"),
            SecretMatch("b.py", 3, "", "Pass", Severity.HIGH, "pw"),
        ]
        by_file = result.matches_by_file()
        self.assertEqual(len(by_file["a.py"]), 2)
        self.assertEqual(len(by_file["b.py"]), 1)


# ---------------------------------------------------------------------------
# 11. All pattern types coverage
# ---------------------------------------------------------------------------

class TestAllPatternTypes(unittest.TestCase):
    """Ensure every declared pattern type is tested at least once."""

    def test_all_patterns_have_names(self):
        """Every pattern should have a human-readable name."""
        from scanner import SECRET_PATTERNS
        for name, severity, pattern in SECRET_PATTERNS:
            self.assertIsInstance(name, str)
            self.assertGreater(len(name), 3)
            self.assertIsInstance(severity, Severity)
            self.assertIsNotNone(pattern)

    def test_pattern_count(self):
        """There should be a reasonable number of patterns."""
        from scanner import SECRET_PATTERNS
        self.assertGreaterEqual(len(SECRET_PATTERNS), 15)

    def test_sendgrid_key(self):
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(
            'SENDGRID_KEY = "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop"',
            "settings.py",
        )
        types = {m.secret_type for m in matches}
        self.assertIn("SendGrid API Key", types)

    def test_webhook_secret(self):
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(
            'WEBHOOK_SECRET="whsec_abcdefghijklmnopqrstuvwxyz123456"',
            "settings.py",
        )
        types = {m.secret_type for m in matches}
        self.assertIn("Webhook Secret", types)

    def test_authorization_header(self):
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(
            'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc',
            "middleware.py",
        )
        types = {m.secret_type for m in matches}
        self.assertIn("Authorization Header", types)

    def test_sensitive_env_var(self):
        scanner = FleetSecretScanner()
        matches = scanner._scan_text(
            'DATABASE_PASSWORD=S3cur3P@ssw0rd\n',
            ".env",
        )
        types = {m.secret_type for m in matches}
        self.assertIn("Sensitive Environment Variable", types)


if __name__ == "__main__":
    unittest.main(verbosity=2)
