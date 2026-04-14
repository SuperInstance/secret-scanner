"""Fleet Secret Scanner — scans git repositories for accidentally committed secrets.

Unlike the keeper's leak detector (which scans outbound requests),
this scanner checks the git history for secrets that shouldn't be there.
"""

from __future__ import annotations

import os
import re
import json
import hashlib
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"  # Live credentials (prod keys, passwords)
    HIGH = "HIGH"          # Private keys, connection strings
    MEDIUM = "MEDIUM"      # API keys, tokens
    LOW = "LOW"            # Tokens in tests, example keys


@dataclass
class SecretMatch:
    """Represents a single secret match found during scanning."""
    file_path: str
    line_number: int
    line_content: str
    secret_type: str
    severity: Severity
    matched_value: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None

    def fingerprint(self) -> str:
        """Create a stable fingerprint for this match (for baseline comparison)."""
        raw = f"{self.file_path}:{self.line_number}:{self.secret_type}:{self.matched_value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "secret_type": self.secret_type,
            "severity": self.severity.value,
            "matched_value": self._redact(),
            "fingerprint": self.fingerprint(),
            "commit_hash": self.commit_hash,
            "commit_message": self.commit_message,
        }

    def _redact(self) -> str:
        """Redact the secret value, showing only first/last chars."""
        val = self.matched_value
        if len(val) <= 8:
            return "****"
        return val[:4] + "*" * (len(val) - 8) + val[-4:]


@dataclass
class ScanResult:
    """Result of a scan operation."""
    repo_path: str
    scan_mode: str
    matches: list[SecretMatch] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    scan_time_ms: float = 0.0
    error: Optional[str] = None

    @property
    def has_secrets(self) -> bool:
        return len(self.matches) > 0

    def severity_counts(self) -> dict[str, int]:
        counts = {}
        for m in self.matches:
            counts[m.severity.value] = counts.get(m.severity.value, 0) + 1
        return counts

    def matches_by_file(self) -> dict[str, list[SecretMatch]]:
        by_file: dict[str, list[SecretMatch]] = {}
        for m in self.matches:
            by_file.setdefault(m.file_path, []).append(m)
        return by_file

    def to_dict(self) -> dict:
        return {
            "repo_path": str(self.repo_path),
            "scan_mode": self.scan_mode,
            "has_secrets": self.has_secrets,
            "total_secrets": len(self.matches),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "severity_counts": self.severity_counts(),
            "matches": [m.to_dict() for m in self.matches],
            "scan_time_ms": round(self.scan_time_ms, 2),
        }


# ---------------------------------------------------------------------------
# Secret patterns — tuned for git history scanning
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, str, Severity, re.Pattern[str]]] = []

def _build_patterns() -> None:
    """Build the compiled pattern list."""
    raw = [
        # GitHub PATs
        (r"(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}",
         "GitHub Personal Access Token", Severity.CRITICAL),

        # AWS Access Key ID
        (r"AKIA[0-9A-Z]{16}",
         "AWS Access Key ID", Severity.CRITICAL),

        # AWS Secret Access Key (contextual)
        (r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?",
         "AWS Secret Access Key", Severity.CRITICAL),

        # Generic API key assignments
        (r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']",
         "Generic API Key", Severity.MEDIUM),

        # Private keys
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
         "Private Key", Severity.HIGH),

        # Connection strings
        (r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s\"']+",
         "Database Connection String", Severity.HIGH),

        (r"(?i)(?:jdbc|sqlserver)://[^\s\"']+",
         "Database Connection String (JDBC)", Severity.HIGH),

        # JWT tokens
        (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
         "JSON Web Token", Severity.HIGH),

        # Slack tokens
        (r"xox[baprs]-[0-9]{10,13}-[0-9A-Za-z]{24,}",
         "Slack Token", Severity.HIGH),

        # Stripe keys
        (r"(?:sk|pk|rk)_live_[A-Za-z0-9]{24,}",
         "Stripe Live Key", Severity.CRITICAL),

        (r"(?:sk|pk|rk)_test_[A-Za-z0-9]{24,}",
         "Stripe Test Key", Severity.MEDIUM),

        # Google API keys
        (r"AIza[0-9A-Za-z\-_]{35}",
         "Google API Key", Severity.MEDIUM),

        # Passwords in code
        (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"']([^\"']{4,})[\"']",
         "Hardcoded Password", Severity.HIGH),

        # SendGrid
        (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
         "SendGrid API Key", Severity.HIGH),

        # Twilio
        (r"SK[0-9a-fA-F]{32}",
         "Twilio API Key", Severity.HIGH),

        # Heroku
        (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}:heroku",
         "Heroku API Key", Severity.HIGH),

        # .env-style assignments with sensitive names
        (r"(?i)^(?:DB_|DATABASE_|SECRET_|AUTH_|TOKEN_|PRIVATE_|ADMIN_|MASTER_)"
         r"(?:PASSWORD|PASS|KEY|TOKEN|SECRET|CREDENTIAL)s?\s*=\s*\S+",
         "Sensitive Environment Variable", Severity.HIGH),

        # Generic high-entropy key-like strings after key= or token=
        (r"(?i)(?:key|token|secret|credential)s?\s*[=:]\s*[\"']([A-Za-z0-9+/=_\-]{32,})[\"']",
         "Generic Secret Assignment", Severity.MEDIUM),

        # Authorization header values
        (r"(?i)Authorization\s*:\s*(?:Bearer|Token)\s+[A-Za-z0-9_\-\.]+",
         "Authorization Header", Severity.HIGH),

        # Webhook secrets
        (r"whsec_[A-Za-z0-9]{32,}",
         "Webhook Secret", Severity.HIGH),
    ]

    for pattern_str, name, severity in raw:
        SECRET_PATTERNS.append((name, severity, re.compile(pattern_str)))

_build_patterns()


# ---------------------------------------------------------------------------
# Default ignore / allow lists
# ---------------------------------------------------------------------------

DEFAULT_IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", ".tox", ".venv", "venv",
    ".eggs", "*.egg-info", ".mypy_cache", ".pytest_cache", ".next",
    ".nuxt", "dist", "build", ".bundle", "vendor", ".idea", ".vscode",
    "coverage", ".nyc_output", ".cache",
}

DEFAULT_IGNORE_FILES = {
    "*.pyc", "*.pyo", "*.so", "*.dylib", "*.dll", "*.exe", "*.bin",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.woff",
    "*.woff2", "*.ttf", "*.eot", "*.lock", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "composer.lock",
    ".secret-scanner-baseline.json",
}

DEFAULT_ALLOW_PATTERNS = [
    # Test fixtures — intentionally contain fake secrets
    r"(?:test|tests|__tests__|spec|specs)/.*",
    r"(?:fixture|fixtures|mock|mocks|fake|fakes)/.*",
    r".*\.test\.(?:py|js|ts|rb|go|java|rs)$",
    r".*\.spec\.(?:py|js|ts|rb|go|java|rs)$",
    r"(?:test_|_test\.|spec_|_spec\.)",
    # Documentation — files in docs/ dir, or named docs/readme/changelog
    r"(?:^|/)docs?/.*",
    r"(?:^|/)(?:README|CHANGELOG|CONTRIBUTING|CODE_OF_CONDUCT)(?:\.md|\.rst|\.txt)?$",
    r"example[s]?/",
    # Known dummy values
    r"(?:YOUR_|REPLACE_|INSERT_|CHANGE_)(?:API_)?(?:KEY|TOKEN|SECRET)",
    r"<(?:API_KEY|TOKEN|SECRET|PASSWORD)>",
    r"\{(?:API_KEY|TOKEN|SECRET|PASSWORD)\}",
    r"\$\{(?:API_KEY|TOKEN|SECRET|PASSWORD)\}",
    r"(?:xxx|example|sample|test|fake|dummy|placeholder|changeme)[-_]",
    r"localhost",
    r"127\.0\.0\.1",
    r"example\.com",
    r"password123",
    r"secret123",
    r"your[_-]?password",
]


class FleetSecretScanner:
    """Scans git repositories for accidentally committed secrets.

    Unlike the keeper's leak detector (which scans outbound requests),
    this scanner checks the git history for secrets that shouldn't be there.
    """

    def __init__(
        self,
        *,
        ignore_dirs: Optional[set[str]] = None,
        ignore_files: Optional[set[str]] = None,
        allow_patterns: Optional[list[str]] = None,
        max_file_size: int = 1024 * 1024,  # 1 MB
    ) -> None:
        self.ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
        self.ignore_files = ignore_files or DEFAULT_IGNORE_FILES
        self.allow_patterns = [
            re.compile(p) for p in (allow_patterns or DEFAULT_ALLOW_PATTERNS)
        ]
        self.max_file_size = max_file_size

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_repo(self, repo_path: str | Path) -> ScanResult:
        """Perform a full repository scan (current files + git history)."""
        repo_path = Path(repo_path).resolve()
        result = ScanResult(repo_path=str(repo_path), scan_mode="full")

        if not repo_path.exists():
            result.error = f"Repository path does not exist: {repo_path}"
            return result

        # Scan current files
        current_result = self._scan_current_files(repo_path)
        result.matches.extend(current_result.matches)
        result.files_scanned += current_result.files_scanned
        result.files_skipped += current_result.files_skipped

        # Scan git history if available
        if self._is_git_repo(repo_path):
            history_result = self._scan_git_history(repo_path)
            result.matches.extend(history_result.matches)
            result.files_scanned += history_result.files_scanned
            result.files_skipped += history_result.files_skipped

        return result

    def scan_commit(self, repo_path: str | Path, commit_hash: str) -> ScanResult:
        """Scan a specific commit in a repository."""
        repo_path = Path(repo_path).resolve()
        result = ScanResult(
            repo_path=str(repo_path),
            scan_mode=f"commit:{commit_hash}",
        )

        try:
            diff_text = self._run_git(
                repo_path, ["log", "-1", "-p", "--format=%H%n%s", commit_hash],
            )
            if diff_text:
                commit_matches = self._scan_text(diff_text, f"commit:{commit_hash}")
                for m in commit_matches:
                    m.commit_hash = commit_hash
                    # Extract commit message
                    lines = diff_text.split("\n")
                    if len(lines) > 1:
                        m.commit_message = lines[1][:200]
                result.matches = commit_matches
                result.files_scanned = 1
        except subprocess.CalledProcessError as exc:
            result.error = f"Failed to scan commit {commit_hash}: {exc}"

        return result

    def scan_diff(self, repo_path: str | Path) -> ScanResult:
        """Scan uncommitted changes (working directory vs HEAD)."""
        repo_path = Path(repo_path).resolve()
        result = ScanResult(
            repo_path=str(repo_path),
            scan_mode="diff",
        )

        try:
            diff_text = self._run_git(repo_path, ["diff"])
            if diff_text:
                matches = self._scan_diff_text(diff_text)
                result.matches = matches
                result.files_scanned = 1
            else:
                result.files_scanned = 0
        except subprocess.CalledProcessError as exc:
            result.error = f"Failed to get diff: {exc}"

        return result

    def scan_staged(self, repo_path: str | Path) -> ScanResult:
        """Scan staged (but uncommitted) changes."""
        repo_path = Path(repo_path).resolve()
        result = ScanResult(
            repo_path=str(repo_path),
            scan_mode="staged",
        )

        try:
            diff_text = self._run_git(repo_path, ["diff", "--cached"])
            if diff_text:
                matches = self._scan_diff_text(diff_text)
                result.matches = matches
                result.files_scanned = 1
            else:
                result.files_scanned = 0
        except subprocess.CalledProcessError as exc:
            result.error = f"Failed to get staged diff: {exc}"

        return result

    def scan_file(self, file_path: str | Path) -> ScanResult:
        """Scan a single file for secrets."""
        file_path = Path(file_path).resolve()
        result = ScanResult(
            repo_path=str(file_path.parent),
            scan_mode="file",
        )

        if not file_path.exists():
            result.error = f"File does not exist: {file_path}"
            return result

        if file_path.is_dir():
            result.error = f"Path is a directory, not a file: {file_path}"
            return result

        if file_path.stat().st_size > self.max_file_size:
            result.files_skipped = 1
            result.error = f"File too large ({file_path.stat().st_size} bytes)"
            return result

        try:
            content = file_path.read_text(errors="replace")
            result.matches = self._scan_text(content, str(file_path))
            result.files_scanned = 1
        except OSError as exc:
            result.error = f"Cannot read file: {exc}"

        return result

    def is_allowed(self, file_path: str) -> bool:
        """Check if a file matches the allow-list (test fixtures, docs, etc.)."""
        for pattern in self.allow_patterns:
            if pattern.search(file_path):
                return True
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_current_files(self, repo_path: Path) -> ScanResult:
        """Scan all files in the working directory."""
        result = ScanResult(repo_path=str(repo_path), scan_mode="current_files")

        for root, dirs, files in os.walk(repo_path):
            # Prune ignored directories
            dirs[:] = sorted(
                d for d in dirs
                if d not in self.ignore_dirs and not self._is_ignored(d, is_dir=True)
            )

            for fname in sorted(files):
                if self._is_ignored(fname, is_dir=False):
                    result.files_skipped += 1
                    continue

                fpath = Path(root) / fname
                rel_path = fpath.relative_to(repo_path)
                rel_str = str(rel_path)

                if self.is_allowed(rel_str):
                    result.files_skipped += 1
                    continue

                if fpath.stat().st_size > self.max_file_size:
                    result.files_skipped += 1
                    continue

                try:
                    content = fpath.read_text(errors="replace")
                    file_matches = self._scan_text(content, rel_str)
                    result.matches.extend(file_matches)
                    result.files_scanned += 1
                except OSError:
                    result.files_skipped += 1

        return result

    def _scan_git_history(self, repo_path: Path) -> ScanResult:
        """Scan git log for secrets."""
        result = ScanResult(repo_path=str(repo_path), scan_mode="git_history")

        try:
            # Use git log -p to get full diffs of all commits
            log_text = self._run_git(
                repo_path,
                ["log", "--all", "-p", "--format=COMMIT_MARKER%n%H%n%B"],
            )
        except subprocess.CalledProcessError as exc:
            result.error = f"Failed to read git log: {exc}"
            return result

        if not log_text:
            return result

        current_commit = None
        current_message = None

        for chunk in log_text.split("COMMIT_MARKER"):
            chunk = chunk.strip()
            if not chunk:
                continue

            lines = chunk.split("\n")
            if len(lines) >= 2:
                current_commit = lines[1].strip()
                # Commit message is the rest until empty line
                msg_lines = []
                for i in range(2, len(lines)):
                    if lines[i].strip() == "" and i > 2:
                        break
                    msg_lines.append(lines[i])
                current_message = " ".join(msg_lines)[:200]

            matches = self._scan_text(chunk, "git_history")
            for m in matches:
                m.commit_hash = current_commit
                m.commit_message = current_message
            result.matches.extend(matches)
            result.files_scanned += 1

        # Deduplicate by fingerprint — keep the one with commit info
        seen: dict[str, SecretMatch] = {}
        for m in result.matches:
            fp = m.fingerprint()
            if fp not in seen or m.commit_hash:
                seen[fp] = m
        result.matches = list(seen.values())

        return result

    def _scan_diff_text(self, diff_text: str) -> list[SecretMatch]:
        """Parse git diff output and scan added lines."""
        matches: list[SecretMatch] = []
        current_file = "unknown"
        line_number = 0

        for line in diff_text.split("\n"):
            # Track file paths in diff headers
            if line.startswith("diff --git"):
                parts = line.split(" b/")
                if len(parts) >= 2:
                    current_file = parts[-1]
                line_number = 0
                continue

            if line.startswith("+++ b/"):
                current_file = line[6:]
                line_number = 0
                continue

            if line.startswith("@@"):
                # Parse hunk header for line numbers
                hunk_match = re.search(r"\+(\d+)", line)
                if hunk_match:
                    line_number = int(hunk_match.group(1)) - 1
                continue

            # Only scan added lines (starting with +)
            if line.startswith("+") and not line.startswith("+++"):
                line_number += 1
                clean = line[1:]  # Strip leading +

                if self.is_allowed(current_file):
                    continue

                for secret_name, severity, pattern in SECRET_PATTERNS:
                    for m in pattern.finditer(clean):
                        matched = m.group(0)
                        if self._is_false_positive(matched, secret_name):
                            continue
                        matches.append(SecretMatch(
                            file_path=current_file,
                            line_number=line_number,
                            line_content=clean,
                            secret_type=secret_name,
                            severity=severity,
                            matched_value=matched,
                        ))
            elif not line.startswith("-"):
                line_number += 1

        return matches

    def _scan_text(
        self, text: str, source: str, context_lines: int = 2,
    ) -> list[SecretMatch]:
        """Scan arbitrary text for secret patterns."""
        matches: list[SecretMatch] = []
        lines = text.split("\n")

        for i, line in enumerate(lines, start=1):
            for secret_name, severity, pattern in SECRET_PATTERNS:
                for m in pattern.finditer(line):
                    matched = m.group(0)
                    if self._is_false_positive(matched, secret_name):
                        continue
                    ctx_before = lines[max(0, i - context_lines - 1): i - 1]
                    ctx_after = lines[i: i + context_lines]
                    matches.append(SecretMatch(
                        file_path=source,
                        line_number=i,
                        line_content=line,
                        secret_type=secret_name,
                        severity=severity,
                        matched_value=matched,
                        context_before=ctx_before,
                        context_after=ctx_after,
                    ))

        return matches

    @staticmethod
    def _is_false_positive(value: str, secret_type: str) -> bool:
        """Filter out common false positives."""
        # Very short matches are likely noise
        if len(value) < 10 and secret_type != "Private Key":
            return True

        # Skip env var references (not values) — must be entire match
        if re.match(r"^\$\{[A-Z_]+\}$", value):
            return True
        if re.match(r"^\$[A-Z_]+$", value):
            return True

        # Skip known placeholder / dummy patterns using word-boundary checks
        # Only match when the placeholder word stands alone, not embedded in real keys
        lower = value.lower()
        placeholder_words = [
            r"\bexample\b", r"\bsample\b", r"\bchangeme\b",
            r"\bplaceholder\b", r"\bxxx+\b", r"\breplaceme\b",
        ]
        for pat in placeholder_words:
            if re.search(pat, lower):
                return True

        # Skip patterns that start with known non-secret prefixes
        non_secret_prefixes = [
            "your_", "replace_", "insert_", "change_",
        ]
        for prefix in non_secret_prefixes:
            if lower.startswith(prefix):
                return True

        # Skip template variable syntax
        if re.match(r"^\$\{[A-Z_]+\}$", value):
            return True
        if re.match(r"^[{<].+[>}]$", value):
            return True

        # Skip very common non-secret connection strings
        if "localhost" in lower or "127.0.0.1" in lower:
            return True
        if "sqlite://" in lower or "sqlite3://" in lower:
            return True

        # Skip values that are clearly test fixtures (start with test_/fake_)
        if re.match(r"^(?:test|fake|mock|dummy)_", lower):
            return True

        return False

    @staticmethod
    def _is_ignored(name: str, *, is_dir: bool) -> bool:
        """Check if a file/directory name matches ignore patterns."""
        # Check exact filename matches
        if not is_dir and name in DEFAULT_IGNORE_FILES:
            return True
        # Check glob-like patterns
        for pattern in DEFAULT_IGNORE_FILES if not is_dir else []:
            if pattern.startswith("*.") and name.endswith(pattern[1:]):
                return True
        return False

    @staticmethod
    def _is_git_repo(path: Path) -> bool:
        """Check if a path is inside a git repository."""
        return (path / ".git").exists()

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

    # ------------------------------------------------------------------
    # Baseline management
    # ------------------------------------------------------------------

    @staticmethod
    def save_baseline(repo_path: str | Path, scan_result: ScanResult, baseline_path: str | Path | None = None) -> Path:
        """Save scan results as a baseline for future comparison."""
        repo_path = Path(repo_path).resolve()
        if baseline_path is None:
            baseline_path = repo_path / ".secret-scanner-baseline.json"

        baseline_path = Path(baseline_path)
        data = {
            "repo_path": str(repo_path),
            "timestamp": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ"),
            "fingerprints": [m.fingerprint() for m in scan_result.matches],
            "summary": scan_result.to_dict(),
        }
        baseline_path.write_text(json.dumps(data, indent=2))
        return baseline_path

    @staticmethod
    def load_baseline(baseline_path: str | Path) -> dict:
        """Load a previously saved baseline."""
        baseline_path = Path(baseline_path)
        if not baseline_path.exists():
            raise FileNotFoundError(f"Baseline not found: {baseline_path}")
        return json.loads(baseline_path.read_text())

    @staticmethod
    def compare_baseline(baseline: dict, current: ScanResult) -> dict:
        """Compare current scan results against a baseline.

        Returns a dict with:
          - new_secrets: secrets not in the baseline
          - removed_secrets: baseline secrets not in current scan
          - unchanged: secrets present in both
        """
        baseline_fps = set(baseline.get("fingerprints", []))
        current_fps: dict[str, SecretMatch] = {
            m.fingerprint(): m for m in current.matches
        }

        new_secrets = [
            m for fp, m in current_fps.items() if fp not in baseline_fps
        ]
        removed = baseline_fps - set(current_fps.keys())
        unchanged = [
            m for fp, m in current_fps.items() if fp in baseline_fps
        ]

        return {
            "new_secrets": [m.to_dict() for m in new_secrets],
            "new_count": len(new_secrets),
            "removed_count": len(removed),
            "unchanged_count": len(unchanged),
            "drift_detected": len(new_secrets) > 0,
            "baseline_timestamp": baseline.get("timestamp"),
            "new_severity_counts": {
                sev: sum(1 for m in new_secrets if m.severity.value == sev)
                for sev in set(m.severity.value for m in new_secrets)
            } if new_secrets else {},
        }
