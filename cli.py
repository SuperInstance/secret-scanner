"""Fleet Secret Scanner — CLI interface.

Subcommands:
    scan <repo_path>        Scan a repository (current files + history)
    scan-all                Scan all fleet repos
    scan-history <repo>     Scan full git history
    scan-diff <repo>        Scan uncommitted changes
    scan-staged <repo>      Scan staged changes
    scan-file <file>        Scan a single file
    baseline save <repo>    Save current state as baseline
    baseline compare <repo> Compare current scan with saved baseline
    report [--format fmt]   Generate report from last scan
    onboard                 Set up the scanner for first use
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from scanner import FleetSecretScanner, ScanResult, Severity
from reporter import ScanReporter
from git_analyzer import GitAnalyzer


# Default fleet repos directory
DEFAULT_FLEET_DIR = Path(__file__).parent.parent


def _print_result(result: ScanResult, fmt: str = "text") -> None:
    """Print scan results in the specified format."""
    reporter = ScanReporter(result)
    if fmt == "json":
        print(reporter.to_json())
    elif fmt == "markdown":
        print(reporter.to_markdown())
    else:
        print(reporter.to_text())


def _print_error(msg: str) -> None:
    """Print an error message to stderr."""
    print(f"ERROR: {msg}", file=sys.stderr)


def _resolve_path(p: str) -> Path:
    """Resolve a path relative to current directory or use default."""
    path = Path(p)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


# ------------------------------------------------------------------
# Subcommand handlers
# ------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    """Scan a single repository."""
    repo_path = _resolve_path(args.repo_path)
    scanner = FleetSecretScanner()
    result = scanner.scan_repo(repo_path)
    _print_result(result, args.format)
    return 1 if result.has_secrets else 0


def cmd_scan_all(args: argparse.Namespace) -> int:
    """Scan all fleet repos."""
    fleet_dir = Path(args.fleet_dir) if args.fleet_dir else DEFAULT_FLEET_DIR
    fleet_dir = _resolve_path(str(fleet_dir))

    if not fleet_dir.exists():
        _print_error(f"Fleet directory not found: {fleet_dir}")
        return 2

    scanner = FleetSecretScanner()
    total_secrets = 0
    repos_scanned = 0
    all_results: list[ScanResult] = []

    for entry in sorted(fleet_dir.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith("."):
            continue

        git_dir = entry / ".git"
        if not git_dir.exists():
            continue

        repos_scanned += 1
        result = scanner.scan_repo(entry)
        all_results.append(result)

        if result.has_secrets:
            total_secrets += len(result.matches)
            print(f"\n⚠ {entry.name}: {len(result.matches)} secret(s) found")
            for m in result.matches:
                print(f"  - [{m.severity.value}] {m.secret_type} in {m.file_path}:{m.line_number}")
        else:
            print(f"✅ {entry.name}: clean")

    print(f"\n{'='*60}")
    print(f"Scanned {repos_scanned} repositories")
    print(f"Total secrets found: {total_secrets}")

    if args.format == "json":
        combined = {
            "fleet_dir": str(fleet_dir),
            "repos_scanned": repos_scanned,
            "total_secrets": total_secrets,
            "results": [r.to_dict() for r in all_results],
        }
        print("\n--- JSON REPORT ---")
        print(json.dumps(combined, indent=2))

    return 1 if total_secrets > 0 else 0


def cmd_scan_history(args: argparse.Namespace) -> int:
    """Scan git history of a repository."""
    repo_path = _resolve_path(args.repo_path)
    scanner = FleetSecretScanner()

    # Check if it's a git repo
    if not (repo_path / ".git").exists():
        _print_error(f"Not a git repository: {repo_path}")
        return 2

    result = scanner.scan_repo(repo_path)
    # Filter to only history matches
    history_matches = [m for m in result.matches if m.commit_hash]

    history_result = ScanResult(
        repo_path=str(repo_path),
        scan_mode="git_history",
        matches=history_matches,
        files_scanned=result.files_scanned,
    )
    _print_result(history_result, args.format)
    return 1 if history_result.has_secrets else 0


def cmd_scan_diff(args: argparse.Namespace) -> int:
    """Scan uncommitted changes."""
    repo_path = _resolve_path(args.repo_path)
    scanner = FleetSecretScanner()
    result = scanner.scan_diff(repo_path)
    _print_result(result, args.format)
    return 1 if result.has_secrets else 0


def cmd_scan_staged(args: argparse.Namespace) -> int:
    """Scan staged changes."""
    repo_path = _resolve_path(args.repo_path)
    scanner = FleetSecretScanner()
    result = scanner.scan_staged(repo_path)
    _print_result(result, args.format)
    return 1 if result.has_secrets else 0


def cmd_scan_file(args: argparse.Namespace) -> int:
    """Scan a single file."""
    file_path = _resolve_path(args.file_path)
    scanner = FleetSecretScanner()
    result = scanner.scan_file(file_path)
    _print_result(result, args.format)
    return 1 if result.has_secrets else 0


def cmd_baseline_save(args: argparse.Namespace) -> int:
    """Save current scan as baseline."""
    repo_path = _resolve_path(args.repo_path)
    scanner = FleetSecretScanner()
    result = scanner.scan_repo(repo_path)

    baseline_path = args.output if args.output else None
    saved = scanner.save_baseline(repo_path, result, baseline_path)

    print(f"Baseline saved to: {saved}")
    print(f"Total secrets tracked: {len(result.matches)}")
    print(f"Fingerprints: {[m.fingerprint() for m in result.matches]}")

    if result.has_secrets:
        print("\n⚠ WARNING: Secrets were found during baseline scan.")
        print("  These secrets are now tracked. New secrets will be flagged.")

    return 0


def cmd_baseline_compare(args: argparse.Namespace) -> int:
    """Compare current scan with saved baseline."""
    repo_path = _resolve_path(args.repo_path)

    # Find baseline
    baseline_path = Path(args.baseline) if args.baseline else repo_path / ".secret-scanner-baseline.json"

    if not baseline_path.exists():
        _print_error(f"No baseline found at: {baseline_path}")
        _print_error("Run 'secret-scanner baseline save <repo>' first.")
        return 2

    scanner = FleetSecretScanner()
    analyzer = GitAnalyzer(scanner)
    current = scanner.scan_repo(repo_path)

    comparison = analyzer.check_baseline_drift(baseline_path, current)

    if args.format == "json":
        print(json.dumps(comparison, indent=2))
    elif args.format == "markdown":
        print(ScanReporter.diff_report_markdown(
            FleetSecretScanner.load_baseline(baseline_path), current,
        ))
    else:
        print(ScanReporter.diff_report(
            FleetSecretScanner.load_baseline(baseline_path), current,
        ))

    return 1 if comparison["drift_detected"] else 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate a report (placeholder — normally reads saved results)."""
    _print_error(
        "The 'report' command requires saved results. "
        "Use 'scan --format json|text|markdown' instead, or pipe results."
    )
    return 2


def cmd_onboard(args: argparse.Namespace) -> int:
    """Set up the scanner for first use."""
    print("Fleet Secret Scanner — Setup")
    print("=" * 40)
    print()

    # Check Python version
    print(f"Python version: {sys.version.split()[0]}")

    # Check for git
    try:
        result = subprocess_run(["git", "--version"])
        print(f"Git: {result.stdout.strip()}")
    except Exception:
        print("Git: NOT FOUND (required for history scanning)")

    print()
    print("Scanner initialized. Available commands:")
    print("  scan <path>          Scan a repository")
    print("  scan-all             Scan all fleet repos")
    print("  scan-history <path>  Scan git history")
    print("  scan-diff <path>     Scan uncommitted changes")
    print("  baseline save <path> Save baseline")
    print("  baseline compare <path> Compare with baseline")
    print()
    print("Secret patterns detected:")
    from scanner import SECRET_PATTERNS
    for name, severity, _ in SECRET_PATTERNS:
        print(f"  [{severity.value:8s}] {name}")

    return 0


def subprocess_run(cmd: list[str]):
    """Compatibility shim for subprocess.run."""
    import subprocess
    return subprocess.run(cmd, capture_output=True, text=True)


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Fleet Secret Scanner — scan git repos for accidentally committed secrets.",
    )

    # Create a shared parent parser for the --format flag so it works
    # both before and after the subcommand
    format_parent = argparse.ArgumentParser(add_help=False)
    format_parent.add_argument(
        "--format", "-f",
        choices=["text", "json", "markdown"],
        default="text",
        dest="format",
        help="Output format (default: text)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan a repository", parents=[format_parent])
    p_scan.add_argument("repo_path", help="Path to the repository")
    p_scan.set_defaults(func=cmd_scan)

    # scan-all
    p_scan_all = subparsers.add_parser("scan-all", help="Scan all fleet repos", parents=[format_parent])
    p_scan_all.add_argument(
        "--fleet-dir", help="Path to fleet repos directory",
    )
    p_scan_all.set_defaults(func=cmd_scan_all)

    # scan-history
    p_hist = subparsers.add_parser("scan-history", help="Scan git history", parents=[format_parent])
    p_hist.add_argument("repo_path", help="Path to the repository")
    p_hist.set_defaults(func=cmd_scan_history)

    # scan-diff
    p_diff = subparsers.add_parser("scan-diff", help="Scan uncommitted changes", parents=[format_parent])
    p_diff.add_argument("repo_path", help="Path to the repository")
    p_diff.set_defaults(func=cmd_scan_diff)

    # scan-staged
    p_staged = subparsers.add_parser("scan-staged", help="Scan staged changes", parents=[format_parent])
    p_staged.add_argument("repo_path", help="Path to the repository")
    p_staged.set_defaults(func=cmd_scan_staged)

    # scan-file
    p_file = subparsers.add_parser("scan-file", help="Scan a single file", parents=[format_parent])
    p_file.add_argument("file_path", help="Path to the file")
    p_file.set_defaults(func=cmd_scan_file)

    # baseline
    p_baseline = subparsers.add_parser("baseline", help="Baseline management", parents=[format_parent])
    baseline_sub = p_baseline.add_subparsers(dest="baseline_command")

    p_bl_save = baseline_sub.add_parser("save", help="Save current state as baseline")
    p_bl_save.add_argument("repo_path", help="Path to the repository")
    p_bl_save.add_argument("--output", "-o", help="Custom baseline file path")
    p_bl_save.set_defaults(func=cmd_baseline_save)

    p_bl_cmp = baseline_sub.add_parser("compare", help="Compare with saved baseline")
    p_bl_cmp.add_argument("repo_path", help="Path to the repository")
    p_bl_cmp.add_argument("--baseline", "-b", help="Path to baseline file")
    p_bl_cmp.set_defaults(func=cmd_baseline_compare)

    # report
    p_report = subparsers.add_parser("report", help="Generate report")
    p_report.set_defaults(func=cmd_report)

    # onboard
    p_onboard = subparsers.add_parser("onboard", help="Set up the scanner")
    p_onboard.set_defaults(func=cmd_onboard)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    # Ensure format has a default (for commands that don't inherit format_parent)
    if not hasattr(args, "format") or args.format is None:
        args.format = "text"

    if args.command == "baseline" and not hasattr(args, "func"):
        parser.parse_args(["baseline", "--help"])
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        _print_error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
