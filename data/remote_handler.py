"""
data/remote_handler.py
======================
Pure-Python WinRM collector for classroom WDAC log collection.

Architecture
------------
Python (this module) owns ALL orchestration:
  - parallel sessions via ThreadPoolExecutor
  - per-PC timeout / retry / error categorisation
  - credential handling (prompt or env-var)
  - CSV writing to logs/

A small embedded PowerShell snippet (data/_ps_snippet.py) runs on each
remote PC and handles only event log querying + XML parsing + JSON output.
No .ps1 files on disk are required — good for exe bundling.

Dependencies
------------
    pip install pywinrm          # includes requests-ntlm automatically

WinRM prerequisites on target PCs (run once as admin, or via GPO):
    Enable-PSRemoting -Force -SkipNetworkProfileCheck

Auth transport
--------------
NTLM is used for local accounts (no domain required).  It provides
challenge-response auth with NTLM message-level encryption over HTTP,
so cleartext credentials are never sent on the wire even on port 5985.
For stricter environments upgrade to HTTPS (port 5986).

EXE / PyInstaller notes
-----------------------
- No __file__-based path resolution in this module (safe when frozen).
- pywinrm bundles fine but may need:
      pyinstaller --hidden-import=winrm.transport ...
"""

from __future__ import annotations

import csv
import getpass
import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

try:
    import winrm
    from winrm.exceptions import WinRMTransportError, WinRMOperationTimeoutError
    _WINRM_AVAILABLE = True
except ImportError:
    winrm                      = None          # type: ignore[assignment]
    WinRMTransportError        = Exception     # type: ignore[misc,assignment]
    WinRMOperationTimeoutError = Exception     # type: ignore[misc,assignment]
    _WINRM_AVAILABLE           = False

from core.functions import (
    col, CYAN, GREEN, RED, YELLOW, DIM,
    natural_sort_key,
    make_log_filename,
)
from data._ps_snippet import build_snippet


# ---------------------------------------------------------------------------
# CSV column order — must match PSCustomObject field names in _ps_snippet.py
# ---------------------------------------------------------------------------
OUTPUT_COLUMNS: list[str] = [
    "TimeCreated", "EventID", "MachineName",
    "FilePath", "ProcessName",
    "RequestedSigningLevel", "ValidatedSigningLevel",
    "PolicyName", "PolicyGUID",
    "SHA1FlatHash", "SHA256FlatHash",
    "Publisher", "Issuer", "OriginalFilename",
    "InternalName", "SISigningScenario",
]

# Special first row written before event data — lets log_parser know exactly
# when this file was collected, independent of event timestamps.
_META_COLLECTION_TS_KEY = "__collection_ts__"

# Internal status tokens (never shown raw to user)
_OK        = "OK"
_OFFLINE   = "OFFLINE"
_TIMEOUT   = "TIMEOUT"
_EMPTY     = "EMPTY"
_FAILED    = "FAILED"
_JSON_ERR  = "JSON_ERROR"


# ─────────────────────────────────────────────────────────────────────────────
# PC RANGE PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_pc_range(range_str: str, max_pcs: int = 25) -> list[str]:
    """
    Convert a range string to a sorted list of PC hostnames.

    Examples
    --------
    "all"         →  ["PC-1", "PC-2", ..., "PC-25"]
    "1-10"        →  ["PC-1", ..., "PC-10"]
    "2-5,8,11-15" →  ["PC-2","PC-3","PC-4","PC-5","PC-8","PC-11",...]
    """
    if not range_str or range_str.strip().lower() == "all":
        return [f"PC-{i}" for i in range(1, max_pcs + 1)]

    numbers: set[int] = set()
    for token in range_str.split(","):
        token = token.strip()
        if "-" in token:
            parts = token.split("-", 1)
            try:
                numbers.update(range(int(parts[0]), int(parts[1]) + 1))
            except ValueError:
                pass
        else:
            try:
                numbers.add(int(token))
            except ValueError:
                pass

    return [f"PC-{n}" for n in sorted(numbers) if 1 <= n <= max_pcs]


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def collect_from_classroom(
    logs_dir:    Path,
    pc_range:    str = "all",
    max_pcs:     int = 25,
    max_events:  int = 5000,
    days_back:   int = 30,
    username:    str = "user",
    password:    str = "",
    throttle:    int = 16,
    timeout_sec: int = 20,
) -> list[Path]:
    """
    Pull WDAC logs from all reachable classroom PCs and save to logs_dir.

    Opens parallel WinRM sessions (NTLM auth) using ThreadPoolExecutor.
    Sends the embedded PowerShell snippet to each PC, receives JSON,
    and writes one CSV per successful PC (overwrites any existing file).

    Parameters
    ----------
    logs_dir     : Folder to write CSV files into (created if missing).
    pc_range     : "all", "1-10", "2-5,8,11-15", etc.
    max_pcs      : Highest PC number in the classroom (used when range="all").
    max_events   : Max events to pull per PC (passed to Get-WinEvent).
    days_back    : How many days back to query the event log.
    username     : Local account name on each target PC.
    password     : Account password. Prompted securely if empty or not set
                   in the WDAC_PASSWORD environment variable.
    throttle     : Max parallel WinRM sessions.
    timeout_sec  : Per-PC WinRM operation timeout in seconds.

    Returns
    -------
    List of Path objects for every CSV successfully written.
    """
    if not _WINRM_AVAILABLE:
        print(col(
            "[!] pywinrm is not installed.\n"
            "    Run:  pip install pywinrm",
            RED,
        ))
        return []

    # Credential resolution: arg > env var > interactive prompt
    if not password:
        password = os.environ.get("WDAC_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Password for '{username}': ")

    pcs     = parse_pc_range(pc_range, max_pcs)
    snippet = build_snippet(max_events=max_events, days_back=days_back)

    print(col(f"\n[*] Targeting {len(pcs)} PC(s):  {pcs[0]} … {pcs[-1]}", CYAN))
    print(col(
        f"[*] max-events={max_events}  days-back={days_back}  "
        f"workers={throttle}  timeout={timeout_sec}s",
        DIM,
    ))
    print()

    logs_dir.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []

    with ThreadPoolExecutor(max_workers=throttle) as pool:
        futures = {
            pool.submit(
                _collect_one_pc,
                pc_name     = pc,
                host        = pc,
                snippet     = snippet,
                username    = username,
                password    = password,
                timeout_sec = timeout_sec,
            ): pc
            for pc in pcs
        }

        for future in as_completed(futures):
            pc_name, rows, status = future.result()
            _print_pc_status(pc_name, status, rows)
            if rows:
                path = _save_csv(rows, pc_name, logs_dir)
                saved.append(path)

    total = len(pcs)
    print()
    print(col(
        f"[+] Done — {len(saved)}/{total} PCs collected"
        + (f", {total - len(saved)} failed/offline" if len(saved) < total else ""),
        GREEN if saved else RED,
    ))
    return saved


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _collect_one_pc(
    pc_name:     str,
    host:        str,
    snippet:     str,
    username:    str,
    password:    str,
    timeout_sec: int,
) -> tuple[str, Optional[list[dict]], str]:
    """
    Open one WinRM session, run the snippet, return (pc_name, rows, status).

    Never raises — all exceptions are caught and reflected in the status string.
    Called from a thread pool; print() calls here are thread-safe on CPython.
    """
    try:
        session = winrm.Session(
            target    = host,
            auth      = (username, password),
            transport = "ntlm",
            operation_timeout_sec  = timeout_sec,
            read_timeout_sec       = timeout_sec + 5,
            server_cert_validation = "ignore",
        )
        result = session.run_ps(snippet)

    except WinRMOperationTimeoutError:
        return pc_name, None, _TIMEOUT
    except WinRMTransportError:
        return pc_name, None, _OFFLINE
    except (OSError, socket.error, ConnectionRefusedError):
        return pc_name, None, _OFFLINE
    except Exception as exc:  # noqa: BLE001
        return pc_name, None, f"{_FAILED}: {exc}"

    # Non-zero exit code means the PS snippet itself errored
    if result.status_code != 0:
        err = result.std_err.decode("utf-8", errors="replace").strip()[:200]
        return pc_name, None, f"{_FAILED} (exit {result.status_code}): {err}"

    raw = result.std_out.decode("utf-8", errors="replace").strip()

    # The snippet prints '[]' when the event log is empty — treat as EMPTY
    if not raw or raw == "[]":
        return pc_name, None, _EMPTY

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        snippet_hint = raw[:80].replace("\n", "\\n")
        return pc_name, None, f"{_JSON_ERR}: {exc}  preview={snippet_hint!r}"

    # ConvertTo-Json returns a plain dict (not list) when only 1 event
    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        return pc_name, None, f"{_FAILED}: unexpected JSON type {type(data).__name__}"

    return pc_name, data, _OK


def _print_pc_status(
    pc_name: str,
    status:  str,
    rows:    Optional[list],
) -> None:
    """Print a coloured one-liner status for this PC."""
    label = f"[{pc_name:<8}]"
    if status == _OK and rows:
        print(col(f"{label} OK  [{len(rows):>5} events]", GREEN))
    elif status == _EMPTY:
        print(col(f"{label} 0 events (log is empty for this period)", DIM))
    elif status == _OFFLINE:
        print(col(f"{label} OFFLINE", RED))
    elif status == _TIMEOUT:
        print(col(f"{label} TIMEOUT", YELLOW))
    else:
        # FAILED / JSON_ERROR — include detail
        print(col(f"{label} {status}", YELLOW))


def _save_csv(
    rows:     list[dict],
    pc_name:  str,
    logs_dir: Path,
) -> Path:
    """
    Write event rows as a CSV.

    Filename is ``wdac_log_PC-7.csv`` (no timestamp) — overwriting the
    previous scan for the same PC is intentional: keeps exactly one file
    per PC, always reflecting the most recent collection.

    The first data row is a metadata sentinel with TimeCreated set to the
    ISO collection timestamp and EventID set to __collection_ts__.  This
    lets log_parser.py show the correct "collected at" time in the report
    header regardless of the age of the actual events.
    """
    from datetime import datetime as _dt
    path = logs_dir / make_log_filename(pc_name)
    collection_ts = _dt.now().strftime("%Y-%m-%dT%H:%M")

    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames   = OUTPUT_COLUMNS,
            extrasaction = "ignore",
        )
        writer.writeheader()
        # Metadata sentinel row — parsed specially by log_parser._parse_single_csv
        writer.writerow({
            "TimeCreated": collection_ts,
            "EventID":     _META_COLLECTION_TS_KEY,
            "MachineName": pc_name,
        })
        writer.writerows(rows)

    return path
