"""
core/main.py
============
Entry point and top-level orchestrator for the WDAC Analyzer tool.

Responsibilities
----------------
  1. Parse CLI arguments and validate inputs
  2. Decide which collection path to take:
       --collect   →  remote_handler.py  (live WinRM pull from classroom PCs)
       (default)   →  logs/ folder       (analyse existing CSV files)
  3. Hand raw CSV paths to log_parser.py
  4. Hand parsed data to report/report.py
  5. Print a terminal summary and tell the user where the report landed

This file intentionally contains NO business logic — it only wires the
other modules together.  Adding a new feature means touching data/ or
report/, not this file.

Usage
-----
    python -m core.main                          # analyse logs/ folder
    python -m core.main --collect                # pull live + analyse
    python -m core.main --collect --pcs 1-10    # pull from subset
    python -m core.main --logs path/to/logs/     # custom log folder
    python -m core.main --out  path/to/reports/  # custom output folder
    python -m core.main --vol-map 3=D            # override NT volume map
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from datetime import datetime

# ── Path bootstrap ───────────────────────────────────────────────
# Ensures `core`, `data`, `report_generator` are importable regardless
# of which directory the user ran from, or how they launched the script.
# Uses __file__ here (before functions.py is importable) only to seed
# sys.path — all runtime path resolution afterwards uses get_base_dir().
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Internal imports ───────────────────────────────────────────────
from core.functions import (
    col, BOLD, CYAN, GREEN, RED, YELLOW, DIM,
    DEFAULT_VOL_MAP,
    natural_sort_key,
    get_base_dir,
)

# Imported lazily inside functions to keep startup fast.


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

_BASE       = get_base_dir()
SCRIPT_DIR  = _BASE              # kept for backward compatibility
LOGS_DIR    = _BASE / "logs"
REPORTS_DIR = _BASE / "reports"


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """
    Define all CLI arguments.

    Kept in its own function so tests can call it without triggering main().
    """
    parser = argparse.ArgumentParser(
        prog="wdac-analyzer",
        description="WDAC Audit Log Analyzer — collect, parse, and report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Collection mode ───────────────────────────────────────────────────────
    collect_grp = parser.add_argument_group("Collection (--collect mode)")
    collect_grp.add_argument(
        "--collect", action="store_true",
        help="Pull live WDAC logs from remote PCs before analysing.",
    )
    collect_grp.add_argument(
        "--pcs", metavar="RANGE", default="all",
        help=(
            "PC range to target. Examples: 'all', '1-10', '2-5,8,11-15'. "
            "Default: all (PC-1 through PC-25)."
        ),
    )
    collect_grp.add_argument(
        "--max-pcs", type=int, default=25, metavar="N",
        help="Highest PC number in the classroom. Default: 25.",
    )
    collect_grp.add_argument(
        "--max-events", type=int, default=5000, metavar="N",
        help="Max events to pull per PC. Default: 5000.",
    )
    collect_grp.add_argument(
        "--days-back", type=int, default=30, metavar="N",
        help="How many days back to query the WDAC event log. Default: 30.",
    )
    collect_grp.add_argument(
        "--username", default="user",
        help="Local account name on each target PC. Default: 'user'.",
    )
    collect_grp.add_argument(
        "--password", default="",
        help=(
            "Account password. If omitted, reads WDAC_PASSWORD env var "
            "or prompts securely at runtime."
        ),
    )
    collect_grp.add_argument(
        "--throttle", type=int, default=16, metavar="N",
        help="Max parallel WinRM sessions. Default: 16.",
    )
    collect_grp.add_argument(
        "--timeout", type=int, default=20, metavar="SEC",
        help="Per-PC WinRM connection timeout in seconds. Default: 20.",
    )

    # ── Analysis options ──────────────────────────────────────────────────────
    analysis_grp = parser.add_argument_group("Analysis")
    analysis_grp.add_argument(
        "--logs", metavar="DIR", default=str(LOGS_DIR),
        help=f"Folder containing CSV log files. Default: {LOGS_DIR}",
    )
    analysis_grp.add_argument(
        "--vol-map", metavar="N=X", nargs="+", default=[],
        help=(
            "Override NT HarddiskVolumeN → drive letter mapping. "
            "Example: --vol-map 3=D 4=E"
        ),
    )

    # ── Output options ────────────────────────────────────────────────────────
    output_grp = parser.add_argument_group("Output")
    output_grp.add_argument(
        "--out", metavar="DIR", default=str(REPORTS_DIR),
        help=f"Folder to write the HTML report into. Default: {REPORTS_DIR}",
    )
    output_grp.add_argument(
        "--no-report", action="store_true",
        help="Skip HTML report generation (terminal summary only).",
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _apply_vol_map(vol_map_args: list[str]) -> None:
    """
    Parse --vol-map N=X entries and apply them to DEFAULT_VOL_MAP in-place.

    Example: ["3=D", "4=E"]  →  DEFAULT_VOL_MAP["harddiskvolume3"] = "D:"
    """
    for mapping in vol_map_args:
        try:
            num, letter = mapping.split("=", 1)
            key   = f"harddiskvolume{num.strip()}"
            drive = letter.strip().rstrip(":").upper() + ":"
            DEFAULT_VOL_MAP[key] = drive
            print(col(f"[*] Volume map override: HarddiskVolume{num.strip()} → {drive}", CYAN))
        except ValueError:
            print(col(f"[!] Bad --vol-map entry: {mapping!r}  (use N=X, e.g. 3=D)", YELLOW))


def _resolve_log_files(logs_dir: Path) -> list[Path]:
    """
    Find all CSV files in *logs_dir*, sorted in natural PC order.

    Exits with a clear error message if the folder doesn't exist or is empty.
    """
    if not logs_dir.exists():
        _fatal(
            f"[!] Logs folder not found: {logs_dir}\n"
            f"    Run with --collect to pull logs, or point --logs at an existing folder."
        )

    csvs = sorted(logs_dir.glob("*.csv"), key=lambda p: natural_sort_key(p.stem))
    if not csvs:
        _fatal(
            f"[!] No CSV files found in: {logs_dir}\n"
            f"    Run with --collect to pull logs from classroom PCs."
        )

    return csvs


def _fatal(msg: str) -> None:
    """Print an error message and exit. Pauses if running double-clicked."""
    print(msg, file=sys.stderr)
    if _is_double_clicked():
        input("\nPress Enter to close...")
    sys.exit(1)


def _is_double_clicked() -> bool:
    """
    Detect whether the script was launched by double-clicking rather than
    from a terminal.  On Windows the console window closes immediately on
    exit unless we pause — this detects that case.

    Uses psutil if available; falls back to checking environment variables
    set by Windows Terminal (WT_SESSION) and similar shells.
    """
    if sys.platform != "win32":
        return False
    try:
        import os
        try:
            import psutil
            parent = psutil.Process(os.getpid()).parent().name().lower()
            shell_parents = {
                "cmd.exe", "powershell.exe", "pwsh.exe",
                "python.exe", "pythonw.exe", "wt.exe",
                "bash.exe", "zsh.exe", "fish.exe", "mintty.exe",
            }
            return parent not in shell_parents
        except ImportError:
            has_terminal_env = any(
                os.environ.get(v)
                for v in ("WT_SESSION", "ConEmuPID", "TERM_PROGRAM")
            )
            return not has_terminal_env
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# ORCHESTRATION
# ─────────────────────────────────────────────────────────────────────────────

def _run_collect(args: argparse.Namespace) -> None:
    """
    Collection phase: call remote_handler to pull logs from classroom PCs.

    On completion, logs are saved to args.logs (default: logs/) with
    filenames like PC-7.csv.  Existing files are overwritten — only the
    most recent scan is kept per PC.
    """
    from data.remote_handler import collect_from_classroom

    collect_from_classroom(
        logs_dir    = Path(args.logs),
        pc_range    = args.pcs,
        max_pcs     = args.max_pcs,
        max_events  = args.max_events,
        days_back   = args.days_back,
        username    = args.username,
        password    = args.password,
        throttle    = args.throttle,
        timeout_sec = args.timeout,
    )


def _run_analysis(
    csv_files:  list[Path],
    out_dir:    Path,
    no_report:  bool,
) -> None:
    """
    Analysis phase: parse CSVs → build report data → generate HTML report.

    Steps
    -----
    1. log_parser.parse_logs(csv_files)       → ParsedData
    2. print terminal summary from ParsedData
    3. report.generate_report(ParsedData)     → reports/report_TIMESTAMP.html
    """
    from data.log_parser         import parse_logs
    from report_generator.report import generate_report

    print(col("[*] Parsing logs...", CYAN))
    parsed = parse_logs(csv_files)
    _print_terminal_summary(parsed)

    if not no_report:
        report_path = generate_report(parsed, out_dir)
        print(col(f"[+] Report → {report_path.resolve()}", GREEN))
    else:
        print(col("[*] --no-report set, skipping HTML generation.", DIM))


def _print_terminal_summary(parsed_data: object) -> None:
    """
    Print the post-analysis summary to stdout using data from ParsedData.
    """
    from data.log_parser import ParsedData
    parsed: ParsedData = parsed_data  # type: ignore
    gs  = parsed.global_stats
    sus = parsed.warnings

    print()
    print(col("═" * 72, CYAN))
    print(col("  WDAC AUDIT LOG ANALYZER", BOLD + CYAN))
    print(col("═" * 72, CYAN))

    # Data quality warnings
    critical = [w for w in sus if "Could not detect" in w or "No FilePath" in w]
    if critical:
        for w in critical:
            print(col(f"  {w}", YELLOW))
        print()

    print(col(f"  TOTAL ACROSS {gs.get('pc_count', 0)} PC(s)", BOLD))
    print()
    print(f"  {'Unique files:':<22} {col(gs.get('total_unique', 0), BOLD)}")
    print(f"  {'  Certified:':<22} {col(gs.get('certified', 0), GREEN)}")
    print(f"  {'  Hash-only:':<22} {col(gs.get('hash_only', 0), YELLOW)}")

    unknown = gs.get('unknown', 0)
    nocert_col = RED + BOLD if unknown > 0 else GREEN
    print(f"  {'  No-cert:':<22} {col(unknown, nocert_col)}")

    print()
    print(col("═" * 72, CYAN))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    double_clicked = _is_double_clicked()

    parser  = build_parser()
    args    = parser.parse_args()

    # ── Apply volume-map overrides before any path parsing ────────────────────
    if args.vol_map:
        _apply_vol_map(args.vol_map)

    # ── Ensure output directory exists ───────────────────────────────────────
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    logs_dir = Path(args.logs)

    # ── Collection phase ──────────────────────────────────────────────────────
    if args.collect:
        logs_dir.mkdir(parents=True, exist_ok=True)
        print(col(f"[*] Collection mode — targeting {args.pcs}", CYAN))
        _run_collect(args)

    # ── Analysis phase ────────────────────────────────────────────────────────
    csv_files = _resolve_log_files(logs_dir)

    print(col(f"[*] Found {len(csv_files)} CSV file(s) in {logs_dir}", CYAN))
    print()

    _run_analysis(csv_files, out_dir, args.no_report)

    if double_clicked:
        input("Press Enter to close...")


if __name__ == "__main__":
    main()
