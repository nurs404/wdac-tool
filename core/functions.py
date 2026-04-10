"""
core/functions.py
=================
Shared utility functions used across the entire project.

Rule: a function lives here if it is called by 2 or more other modules.
Rule: nothing here does I/O — no file reads, no subprocesses, no printing.
Rule: no imports from other project modules (this file has zero internal deps).

Sections
--------
  EXE compat       — PyInstaller-safe base directory resolution
  ANSI / terminal  — colour helpers for consistent CLI output
  Sorting          — natural PC-number sort
  Hash             — WDAC flat-hash normalisation
  Path             — NT device path → Win32 drive path
  Timestamp        — flexible WDAC timestamp parsing
  XML              — XML character escaping for policy generation
  PC name          — extract PC identifier from various sources
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# EXE / PYINSTALLER COMPAT
# ─────────────────────────────────────────────────────────────────────────────

def get_base_dir() -> Path:
    """
    Return the project root directory whether running from source or a
    frozen PyInstaller executable.

    Source:  __file__ is  core/functions.py  → parent.parent = project root
    Frozen:  sys.executable is the .exe      → parent        = project root
             (PyInstaller sets sys.frozen=True and extracts files to a temp
              dir; __file__ points there, not next to the .exe — so we use
              sys.executable.parent instead.)
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# ANSI / TERMINAL
# ─────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"


def col(text: object, color: str) -> str:
    """Wrap *text* in an ANSI colour/style code and reset afterward."""
    return f"{color}{text}{RESET}"


# ─────────────────────────────────────────────────────────────────────────────
# SORTING
# ─────────────────────────────────────────────────────────────────────────────

def natural_sort_key(pc_name: str) -> int:
    """
    Numeric sort key for PC names.

    Ensures PC-1, PC-2, …, PC-10, PC-11 order instead of the default
    lexicographic PC-1, PC-10, PC-11, PC-2 order.

    Returns 0 for names with no embedded number (sorts them first).
    """
    m = re.search(r'(\d+)', pc_name)
    return int(m.group(1)) if m else 0


# ─────────────────────────────────────────────────────────────────────────────
# HASH NORMALISATION
# ─────────────────────────────────────────────────────────────────────────────

_DECIMAL_BYTES_RE = re.compile(r'^\d+(\s+\d+)+$')
_HEX_RE           = re.compile(r'^[0-9A-Fa-f]{32,}$')


def flat_hash_to_hex(raw: str) -> str:
    """
    Normalise a WDAC flat hash to an uppercase hex string.

    WDAC events store SHA256/SHA1 as space-separated decimal bytes when the
    data comes through PowerShell Properties[] array serialisation:
        "99 166 43 151 106 0 54 231 ..."  →  "63A62B97..."

    The embedded PS snippet uses XML-named node parsing which returns
    hashes as proper hex already, but this function is kept for legacy CSV
    compatibility and as a defensive normalisation step.

    Accepted inputs
    ---------------
    • Decimal bytes  "99 166 43..."  →  "63A62B97..."   (convert)
    • Already hex    "63A62B97..."   →  "63A62B97..."   (upper-case only)
    • Empty / junk   ""              →  ""              (return as-is)
    """
    raw = raw.strip()
    if not raw:
        return ""
    if _DECIMAL_BYTES_RE.match(raw):
        try:
            return "".join(f"{int(b):02X}" for b in raw.split())
        except ValueError:
            return raw
    if _HEX_RE.match(raw):
        return raw.upper()
    return raw  # unknown format — pass through unchanged


# ─────────────────────────────────────────────────────────────────────────────
# NT PATH RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────

# Best-guess NT volume → drive letter mapping.
# The *real* mapping requires querying the live OS (fsutil / mountvol).
# Volume3 → C: is correct on the vast majority of consumer and classroom installs.
# Overridable at runtime via CLI --vol-map.
DEFAULT_VOL_MAP: dict[str, str] = {
    "harddiskvolume1": "V1:",   # MBR reserved / Recovery — rare in WDAC logs
    "harddiskvolume2": "V2:",   # EFI System Partition — rare in WDAC logs
    "harddiskvolume3": "C:",    # OS drive on almost all standard installs
    "harddiskvolume4": "D:",
    "harddiskvolume5": "E:",
}

_NT_PATH_RE = re.compile(
    r'^\\Device\\(HarddiskVolume\d+)\\?(.*)$',
    re.IGNORECASE,
)


def nt_to_win32_path(path: str, vol_map: dict[str, str] | None = None) -> str:
    """
    Convert an NT device path to a Win32 drive-letter path.

    ``\\Device\\HarddiskVolume3\\Windows\\explorer.exe``
    →  ``C:\\Windows\\explorer.exe``

    Paths that don't match the NT pattern are returned unchanged.
    Pass *vol_map* to override individual volume → letter assignments.
    """
    effective = vol_map if vol_map is not None else DEFAULT_VOL_MAP
    m = _NT_PATH_RE.match(path)
    if not m:
        return path
    drive = effective.get(m.group(1).lower(), f"[{m.group(1)}]")
    rest  = m.group(2)
    return f"{drive}\\{rest}" if rest else f"{drive}\\"


# ─────────────────────────────────────────────────────────────────────────────
# TIMESTAMP PARSING
# ─────────────────────────────────────────────────────────────────────────────

_TS_FORMATS: tuple[str, ...] = (
    "%d.%m.%Y %H:%M:%S",   # European — Get-WinEvent default: 16.02.2026 14:50:10
    "%Y-%m-%d %H:%M:%S",   # ISO-like
    "%m/%d/%Y %H:%M:%S",   # US format
    "%Y-%m-%dT%H:%M:%S",   # ISO 8601 with T separator
)


def parse_timestamp(ts_str: str) -> datetime | None:
    """
    Parse a timestamp string from a WDAC CSV into a :class:`datetime`.

    Returns ``None`` if the string is empty or matches no known format.
    Callers must handle ``None`` (displayed as "—" in the HTML report).
    """
    if not ts_str or not ts_str.strip():
        return None
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# XML SANITISATION
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_xml(text: str) -> str:
    """
    Escape the five XML special characters in *text*.

    Used by report/report.py when embedding data into HTML attributes and
    by report.py when generating WDAC policy XML <Allow> elements.
    """
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


# ─────────────────────────────────────────────────────────────────────────────
# PC NAME HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_PC_FROM_FILENAME_RE = re.compile(
    r'^([^/\\]+)\.csv$',
    re.IGNORECASE,
)


def pc_name_from_filename(filename: str) -> str:
    """
    Extract the PC identifier from a log filename produced by remote_handler.py.

    ``PC-7.csv``  →  ``PC-7``

    Falls back to the full stem if the pattern doesn't match.

    Note: log_parser.py reads PC identity from the MachineName column in
    the CSV *content* — this function is only for display purposes (e.g.
    listing files in the logs/ directory).
    """
    m = _PC_FROM_FILENAME_RE.search(Path(filename).name)
    return m.group(1) if m else Path(filename).stem


def make_log_filename(pc_name: str) -> str:
    """
    Build the canonical log filename for a given PC.

    ``PC-7``  →  ``wdac_log_PC-7.csv``

    No timestamp: overwriting the file on each collection run is intentional
    — this keeps exactly one file per PC (the most recent scan).
    PC identity is read from the MachineName column inside the CSV, not
    from the filename, so renaming the file doesn't break analysis.
    """
    return f"wdac_log_{pc_name}.csv"
