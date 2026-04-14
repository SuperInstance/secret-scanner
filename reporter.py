"""Scan Reporter — generates secret scan reports in multiple formats."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scanner import ScanResult, SecretMatch, Severity, FleetSecretScanner


class ScanReporter:
    """Generate secret scan reports.

    Supports JSON, human-readable text, and Markdown formats.
    Also generates diff reports comparing two scan results.
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result

    # ------------------------------------------------------------------
    # Format generators
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Generate a JSON report with structured data."""
        data = {
            "report_version": "1.0",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scanner": "FleetSecretScanner",
            **self.result.to_dict(),
        }
        return json.dumps(data, indent=indent)

    def to_text(self) -> str:
        """Generate a human-readable text report."""
        lines: list[str] = []
        r = self.result

        lines.append("=" * 72)
        lines.append("  FLEET SECRET SCAN REPORT")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"  Repository : {r.repo_path}")
        lines.append(f"  Scan Mode  : {r.scan_mode}")
        lines.append(f"  Generated  : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"  Files Scanned: {r.files_scanned}")
        lines.append(f"  Files Skipped: {r.files_skipped}")
        lines.append("")

        if r.error:
            lines.append(f"  ERROR: {r.error}")
            lines.append("")
            return "\n".join(lines)

        if not r.has_secrets:
            lines.append("  ✓ No secrets found. Repository is clean.")
            lines.append("")
            return "\n".join(lines)

        # Severity summary
        sev_counts = r.severity_counts()
        total = len(r.matches)

        lines.append(f"  ⚠  {total} secret(s) found!")
        lines.append("")
        lines.append("  Severity Breakdown:")
        lines.append("  " + "-" * 40)

        for sev_level in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = sev_counts.get(sev_level.value, 0)
            if count:
                indicator = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🔵",
                }[sev_level]
                lines.append(f"    {indicator} {sev_level.value:10s} : {count}")
        lines.append("")

        # Group by file
        by_file = r.matches_by_file()
        lines.append(f"  Affected Files ({len(by_file)}):")
        lines.append("  " + "-" * 40)

        for fpath, matches in sorted(by_file.items()):
            lines.append(f"  📄 {fpath} ({len(matches)} secret(s))")
        lines.append("")

        # Detailed findings
        lines.append("  Detailed Findings:")
        lines.append("  " + "-" * 40)
        lines.append("")

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        sorted_matches = sorted(r.matches, key=lambda m: severity_order.get(m.severity, 99))

        for i, m in enumerate(sorted_matches, 1):
            sev_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
            }.get(m.severity, "⚪")

            lines.append(f"  [{i}] {sev_icon} {m.severity.value} — {m.secret_type}")
            lines.append(f"      File : {m.file_path}:{m.line_number}")
            lines.append(f"      Value: {m._redact()}")

            if m.commit_hash:
                short = m.commit_hash[:8]
                lines.append(f"      Commit: {short} {m.commit_message or ''}")

            # Show the matching line (truncated)
            content = m.line_content.strip()[:120]
            if len(m.line_content.strip()) > 120:
                content += "..."
            lines.append(f"      Line : {content}")
            lines.append("")

        lines.append("=" * 72)
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Generate a Markdown report suitable for wikis."""
        lines: list[str] = []
        r = self.result

        lines.append("# Fleet Secret Scan Report")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Repository** | `{r.repo_path}` |")
        lines.append(f"| **Scan Mode** | {r.scan_mode} |")
        lines.append(f"| **Generated** | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |")
        lines.append(f"| **Files Scanned** | {r.files_scanned} |")
        lines.append(f"| **Files Skipped** | {r.files_skipped} |")
        lines.append("")

        if r.error:
            lines.append(f"> ⚠️ Error: {r.error}")
            return "\n".join(lines)

        if not r.has_secrets:
            lines.append("## ✅ Result: No secrets found")
            lines.append("")
            lines.append("Repository is clean — no secrets detected.")
            return "\n".join(lines)

        total = len(r.matches)
        sev_counts = r.severity_counts()

        lines.append(f"## ⚠️ Result: {total} secret(s) found")
        lines.append("")
        lines.append("### Severity Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev_level in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = sev_counts.get(sev_level.value, 0)
            if count:
                badge = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🔵",
                }[sev_level]
                lines.append(f"| {badge} {sev_level.value} | {count} |")
        lines.append("")

        # File summary table
        by_file = r.matches_by_file()
        lines.append(f"### Affected Files ({len(by_file)})")
        lines.append("")
        lines.append("| File | Secrets |")
        lines.append("|------|---------|")
        for fpath, matches in sorted(by_file.items()):
            lines.append(f"| `{fpath}` | {len(matches)} |")
        lines.append("")

        # Detailed findings
        lines.append("### Detailed Findings")
        lines.append("")

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        sorted_matches = sorted(r.matches, key=lambda m: severity_order.get(m.severity, 99))

        for i, m in enumerate(sorted_matches, 1):
            sev_badge = {
                Severity.CRITICAL: "🔴 CRITICAL",
                Severity.HIGH: "🟠 HIGH",
                Severity.MEDIUM: "🟡 MEDIUM",
                Severity.LOW: "🔵 LOW",
            }.get(m.severity, "⚪ UNKNOWN")

            lines.append(f"#### [{i}] {sev_badge} — {m.secret_type}")
            lines.append("")
            lines.append(f"- **File:** `{m.file_path}:{m.line_number}`")
            lines.append(f"- **Redacted Value:** `{m._redact()}`")
            if m.commit_hash:
                lines.append(f"- **Commit:** `{m.commit_hash[:8]}` — {m.commit_message or 'no message'}")
            lines.append("")
            lines.append("```")
            lines.append(m.line_content.strip()[:200])
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Diff report
    # ------------------------------------------------------------------

    @staticmethod
    def diff_report(baseline: dict, current: ScanResult) -> str:
        """Generate a text report comparing baseline with current scan."""
        comparison = FleetSecretScanner.compare_baseline(baseline, current)
        lines: list[str] = []

        lines.append("=" * 72)
        lines.append("  BASELINE DRIFT REPORT")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"  Baseline    : {comparison['baseline_timestamp']}")
        lines.append(f"  Current Scan: {current.scan_mode}")
        lines.append(f"  Repository  : {current.repo_path}")
        lines.append("")

        if comparison["drift_detected"]:
            lines.append(f"  🚨 DRIFT DETECTED — {comparison['new_count']} NEW secret(s)!")
        else:
            lines.append("  ✅ No drift detected — scan matches baseline.")
        lines.append("")

        lines.append(f"  New secrets    : {comparison['new_count']}")
        lines.append(f"  Removed secrets: {comparison['removed_count']}")
        lines.append(f"  Unchanged      : {comparison['unchanged_count']}")
        lines.append("")

        if comparison["new_severity_counts"]:
            lines.append("  New Secrets by Severity:")
            lines.append("  " + "-" * 40)
            for sev, count in comparison["new_severity_counts"].items():
                lines.append(f"    {sev}: {count}")
            lines.append("")

        if comparison["new_secrets"]:
            lines.append("  New Secrets Detail:")
            lines.append("  " + "-" * 40)
            for i, secret in enumerate(comparison["new_secrets"], 1):
                lines.append(f"    [{i}] {secret['severity']} — {secret['secret_type']}")
                lines.append(f"        File  : {secret['file_path']}:{secret['line_number']}")
                lines.append(f"        Value : {secret['matched_value']}")
                lines.append("")

        lines.append("=" * 72)
        return "\n".join(lines)

    @staticmethod
    def diff_report_markdown(baseline: dict, current: ScanResult) -> str:
        """Generate a Markdown diff report."""
        comparison = FleetSecretScanner.compare_baseline(baseline, current)
        lines: list[str] = []

        lines.append("# Baseline Drift Report")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Baseline** | {comparison['baseline_timestamp']} |")
        lines.append(f"| **Scan Mode** | {current.scan_mode} |")
        lines.append(f"| **Repository** | `{current.repo_path}` |")
        lines.append(f"| **Drift Detected** | {'🚨 Yes' if comparison['drift_detected'] else '✅ No'} |")
        lines.append(f"| **New Secrets** | {comparison['new_count']} |")
        lines.append(f"| **Removed Secrets** | {comparison['removed_count']} |")
        lines.append(f"| **Unchanged** | {comparison['unchanged_count']} |")
        lines.append("")

        if comparison["new_secrets"]:
            lines.append("## New Secrets")
            lines.append("")
            lines.append("| # | Severity | Type | File | Line |")
            lines.append("|---|----------|------|------|------|")
            for i, secret in enumerate(comparison["new_secrets"], 1):
                lines.append(
                    f"| {i} | {secret['severity']} | {secret['secret_type']} | "
                    f"`{secret['file_path']}` | {secret['line_number']} |"
                )
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Save helpers
    # ------------------------------------------------------------------

    def save(self, output_path: str | Path, fmt: str = "text") -> Path:
        """Save report to a file.

        Args:
            output_path: Where to write the report.
            fmt: One of 'json', 'text', 'markdown'.
        """
        output_path = Path(output_path)
        generators = {
            "json": self.to_json,
            "text": self.to_text,
            "markdown": self.to_markdown,
        }
        if fmt not in generators:
            raise ValueError(f"Unknown format: {fmt}. Use: {', '.join(generators)}")

        content = generators[fmt]()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
        return output_path
