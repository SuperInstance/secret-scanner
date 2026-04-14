"""Git History Analyzer — analyzes git repositories for secret-related activity."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from scanner import (
    FleetSecretScanner,
    ScanResult,
    SecretMatch,
    Severity,
)


@dataclass
class CommitInfo:
    """Information about a single git commit."""
    hash: str
    short_hash: str
    author: str
    email: str
    date: str
    message: str
    subject: str


@dataclass
class SecretCommit:
    """A commit that introduced a secret."""
    commit: CommitInfo
    secrets: list[SecretMatch] = field(default_factory=list)
    files_affected: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "commit": {
                "hash": self.commit.hash,
                "short_hash": self.commit.short_hash,
                "author": self.commit.author,
                "email": self.commit.email,
                "date": self.commit.date,
                "message": self.commit.message,
                "subject": self.commit.subject,
            },
            "secrets_found": len(self.secrets),
            "severity_counts": {
                sev: sum(1 for s in self.secrets if s.severity.value == sev)
                for sev in set(s.severity.value for s in self.secrets)
            },
            "files_affected": self.files_affected,
            "details": [s.to_dict() for s in self.secrets],
        }


class GitAnalyzer:
    """Analyze git history for secret patterns.

    This module provides tools to walk through commit history,
    find which commits introduced secrets, and track baseline drift.
    """

    def __init__(self, scanner: Optional[FleetSecretScanner] = None) -> None:
        self.scanner = scanner or FleetSecretScanner()

    # ------------------------------------------------------------------
    # Commit listing
    # ------------------------------------------------------------------

    def get_all_commits(self, repo_path: str | Path) -> list[CommitInfo]:
        """List all commits in a repository.

        Args:
            repo_path: Path to the git repository.

        Returns:
            List of CommitInfo objects, newest first.
        """
        repo_path = Path(repo_path).resolve()
        fmt = "%H%n%h%n%an%n%ae%n%aI%n%s%n%B%n---COMMIT_SEP---"
        output = self._run_git(repo_path, [
            "log", "--all", f"--format={fmt}",
        ])

        commits: list[CommitInfo] = []
        blocks = output.split("---COMMIT_SEP---")

        for block in blocks:
            block = block.strip()
            if not block:
                continue

            lines = block.split("\n")
            if len(lines) < 6:
                continue

            commits.append(CommitInfo(
                hash=lines[0].strip(),
                short_hash=lines[1].strip(),
                author=lines[2].strip(),
                email=lines[3].strip(),
                date=lines[4].strip(),
                subject=lines[5].strip(),
                message="\n".join(lines[5:]).strip(),
            ))

        return commits

    # ------------------------------------------------------------------
    # Diff extraction
    # ------------------------------------------------------------------

    def get_commit_diff(self, repo_path: str | Path, commit_hash: str) -> str:
        """Get the full diff for a single commit.

        Args:
            repo_path: Path to the git repository.
            commit_hash: The commit hash to inspect.

        Returns:
            The diff output as a string.
        """
        repo_path = Path(repo_path).resolve()
        return self._run_git(repo_path, [
            "show", "--format=", commit_hash,
        ])

    def get_commit_files(self, repo_path: str | Path, commit_hash: str) -> list[str]:
        """Get the list of files changed in a commit."""
        repo_path = Path(repo_path).resolve()
        output = self._run_git(repo_path, [
            "diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash,
        ])
        return [f for f in output.strip().split("\n") if f.strip()]

    # ------------------------------------------------------------------
    # File at specific commit
    # ------------------------------------------------------------------

    def get_file_at_commit(
        self, repo_path: str | Path, commit_hash: str, file_path: str,
    ) -> str:
        """Get the contents of a file at a specific commit.

        Args:
            repo_path: Path to the git repository.
            commit_hash: The commit to look at.
            file_path: Path to the file within the repo.

        Returns:
            The file contents as a string.

        Raises:
            subprocess.CalledProcessError: If the file doesn't exist at that commit.
        """
        repo_path = Path(repo_path).resolve()
        return self._run_git(repo_path, [
            "show", f"{commit_hash}:{file_path}",
        ])

    # ------------------------------------------------------------------
    # Secret-introducing commit detection
    # ------------------------------------------------------------------

    def find_secret_introducing_commits(
        self, repo_path: str | Path, max_commits: int = 500,
    ) -> list[SecretCommit]:
        """Find commits that introduced secrets into the repository.

        This walks through commit history and checks each commit's diff
        for secret patterns.

        Args:
            repo_path: Path to the git repository.
            max_commits: Maximum number of commits to scan (default: 500).

        Returns:
            List of SecretCommit objects, ordered newest first.
        """
        repo_path = Path(repo_path).resolve()
        commits = self.get_all_commits(repo_path)[:max_commits]
        secret_commits: list[SecretCommit] = []

        for commit in commits:
            try:
                diff_text = self.get_commit_diff(repo_path, commit.hash)
            except subprocess.CalledProcessError:
                continue

            if not diff_text.strip():
                continue

            # Scan the diff
            matches = self._scan_diff_for_secrets(diff_text, commit)

            if matches:
                try:
                    files = self.get_commit_files(repo_path, commit.hash)
                except subprocess.CalledProcessError:
                    files = []

                secret_commits.append(SecretCommit(
                    commit=commit,
                    secrets=matches,
                    files_affected=files,
                ))

        return secret_commits

    # ------------------------------------------------------------------
    # Baseline drift
    # ------------------------------------------------------------------

    def check_baseline_drift(
        self,
        baseline_path: str | Path,
        current_results: ScanResult,
    ) -> dict:
        """Compare current scan results against a saved baseline.

        Args:
            baseline_path: Path to the baseline JSON file.
            current_results: The current scan results.

        Returns:
            A comparison dict with new/removed/unchanged secrets.

        Raises:
            FileNotFoundError: If the baseline file doesn't exist.
        """
        baseline = FleetSecretScanner.load_baseline(baseline_path)
        return FleetSecretScanner.compare_baseline(baseline, current_results)

    def save_current_baseline(
        self,
        repo_path: str | Path,
        current_results: ScanResult,
        baseline_path: str | Path | None = None,
    ) -> Path:
        """Save current scan results as a new baseline.

        Args:
            repo_path: Path to the repository.
            current_results: The scan results to save.
            baseline_path: Optional custom path for the baseline file.

        Returns:
            Path to the saved baseline file.
        """
        return FleetSecretScanner.save_baseline(
            repo_path, current_results, baseline_path,
        )

    # ------------------------------------------------------------------
    # Repository summary
    # ------------------------------------------------------------------

    def repo_summary(self, repo_path: str | Path) -> dict:
        """Get a summary of a repository's git state.

        Returns:
            Dict with branch, commit count, recent activity, etc.
        """
        repo_path = Path(repo_path).resolve()

        try:
            branch = self._run_git(repo_path, [
                "rev-parse", "--abbrev-ref", "HEAD",
            ]).strip()
        except subprocess.CalledProcessError:
            branch = "unknown"

        try:
            commit_count = int(self._run_git(repo_path, [
                "rev-list", "--count", "HEAD",
            ]).strip())
        except (subprocess.CalledProcessError, ValueError):
            commit_count = 0

        try:
            latest = self._run_git(repo_path, [
                "log", "-1", "--format=%H%n%an%n%aI%n%s",
            ]).strip().split("\n")
            latest_commit = {
                "hash": latest[0] if len(latest) > 0 else "",
                "author": latest[1] if len(latest) > 1 else "",
                "date": latest[2] if len(latest) > 2 else "",
                "message": latest[3] if len(latest) > 3 else "",
            }
        except (subprocess.CalledProcessError, IndexError):
            latest_commit = {}

        try:
            remotes = self._run_git(repo_path, ["remote", "-v"]).strip()
            has_remote = bool(remotes)
        except subprocess.CalledProcessError:
            has_remote = False

        return {
            "path": str(repo_path),
            "branch": branch,
            "total_commits": commit_count,
            "latest_commit": latest_commit,
            "has_remote": has_remote,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_diff_for_secrets(
        self, diff_text: str, commit: CommitInfo,
    ) -> list[SecretMatch]:
        """Scan diff text and attach commit info to matches."""
        matches: list[SecretMatch] = []
        current_file = "unknown"
        line_number = 0

        for line in diff_text.split("\n"):
            if line.startswith("diff --git"):
                parts = line.split(" b/")
                if len(parts) >= 2:
                    current_file = parts[-1]
                line_number = 0
                continue

            if line.startswith("@@"):
                hunk_match = re.search(r"\+(\d+)", line)
                if hunk_match:
                    line_number = int(hunk_match.group(1)) - 1
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_number += 1
                clean = line[1:]

                if self.scanner.is_allowed(current_file):
                    continue

                from scanner import SECRET_PATTERNS
                for secret_name, severity, pattern in SECRET_PATTERNS:
                    for m in pattern.finditer(clean):
                        matched = m.group(0)
                        if FleetSecretScanner._is_false_positive(matched, secret_name):
                            continue
                        matches.append(SecretMatch(
                            file_path=current_file,
                            line_number=line_number,
                            line_content=clean,
                            secret_type=secret_name,
                            severity=severity,
                            matched_value=matched,
                            commit_hash=commit.hash,
                            commit_message=commit.subject,
                        ))
            elif not line.startswith("-"):
                line_number += 1

        return matches

    @staticmethod
    def _run_git(repo_path: Path, args: list[str]) -> str:
        """Run a git command and return stdout."""
        result = subprocess.run(
            ["git", "-C", str(repo_path)] + args,
            capture_output=True,
            text=True,
            timeout=120,
        )
        result.check_returncode()
        return result.stdout
