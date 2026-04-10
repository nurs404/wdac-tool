"""
data/log_parser.py
==================
Parses raw WDAC log CSV files and produces a ``ParsedData`` object that
report/report.py consumes directly.

Responsibilities
----------------
  - Read one or more CSV files from logs/
  - Detect PC name from the MachineName column in file CONTENT, not filename
  - Normalise all hashes to uppercase hex (legacy decimal-byte format handled)
  - Deduplicate events by (filepath, sha256) within and across PCs
  - Classify each unique file: microsoft / publisher_signed / hash_only / unknown
  - Compute all statistics that report.py needs (total, unique, per-category counts)
  - Return everything in a single ``ParsedData`` object so report.py does
    zero counting, zero looping — it just renders

PC name detection
-----------------
PC name is read from the ``MachineName`` column in the CSV content.
It is NEVER inferred from the filename.  This is deliberate:
  - Filenames can be renamed, copied, or merged
  - MachineName is set by ``$env:COMPUTERNAME`` on the remote PC itself
  - This also means one CSV file with multiple MachineName values (e.g.
    a merged export) is handled correctly — each unique machine gets its
    own bucket

ParsedData schema
-----------------
See the ``ParsedData`` dataclass below for the full specification.
report.py imports ParsedData and accesses its fields directly.
"""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.functions import (
    flat_hash_to_hex,
    nt_to_win32_path,
    parse_timestamp,
    natural_sort_key,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

WDAC_EVENT_IDS: frozenset[str] = frozenset({"3076", "3077", "3033", "3034"})

# Windows built-in policy GUIDs — events with these GUIDs are from inbox policies
WINDOWS_POLICY_GUIDS: frozenset[str] = frozenset({
    "{60FD87F8-4593-44A0-91B0-2E0DA022F248}",
    "{0283AC0F-FFF1-49AE-ADA1-8A933130CAD6}",
    "{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}",
    "{0939ED82-BFD5-4D32-B58E-D31D3C49715A}",
    "{1283AC0F-FFF1-49AE-ADA1-8A933130CAD6}",
    "{1939ED82-BFD5-4D32-B58E-D31D3C49715A}",
    "{1678656C-05EF-481F-BC5B-EBD8C991502D}",
    "{2678656C-05EF-481F-BC5B-EBD8C991502D}",
})

MICROSOFT_PUBLISHERS: tuple[str, ...] = (
    "microsoft corporation",
    "microsoft windows",
    "o=microsoft corporation",
)

SYSTEM_PATHS: tuple[str, ...] = (
    r"c:\windows\\",
    r"c:\program files\windows ",
    r"c:\program files (x86)\windows ",
    r"c:\program files\common files\microsoft",
)

# Column aliases: maps our canonical name → possible CSV header spellings
# _ps_snippet.py uses the first spelling; fallbacks handle legacy exports
COL_ALIASES: dict[str, list[str]] = {
    "filepath":              ["FilePath", "filepath", "File Name", "FileName"],
    "publisher":             ["Publisher", "publisher", "PublisherName"],
    "sha256":                ["SHA256FlatHash", "sha256", "SHA256Hash"],
    "sha1":                  ["SHA1FlatHash",   "sha1",   "SHA1Hash"],
    "eventid":               ["EventID", "eventid", "Event ID"],
    "timecreated":           ["TimeCreated", "timecreated", "Time Created"],
    "processname":           ["ProcessName", "processname", "Process Name"],
    "policyname":            ["PolicyName", "policyname", "Policy Name"],
    "policyguid":            ["PolicyGUID", "policyguid", "PolicyId", "Policy Id"],
    "machinename":           ["MachineName", "machinename", "Computer", "PSComputerName"],
    "originalfilename":      ["OriginalFilename", "OriginalFileName", "originalfilename"],
    "issuer":                ["Issuer", "issuer"],
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    """One unique (filepath, sha256) record, enriched and deduplicated."""

    filepath:         str
    filename:         str                   # basename of filepath
    extension:        str                   # lowercase suffix: ".exe"
    publisher:        str                   # cert CN; "" for unsigned
    sha256:           str                   # uppercase hex; "" if unavailable
    sha1:             str
    eventid:          str
    timecreated:      str
    dt:               Optional[datetime]    # parsed from timecreated
    processname:      str
    policyname:       str
    policyguid:       str
    policy_type:      str                   # "windows" | "custom"
    originalfilename: str
    issuer:           str                   # cert issuer CN; "" if unavailable
    category:         str                   # see classify()
    pcs:              list[str]             # which PCs have this file
    pc_hits:          dict[str, int]        # {pc_name: hit_count}
    total_hits:       int
    all_timestamps:   list[tuple[datetime, str, int]]  # (dt, pc, count)
    first_seen:       Optional[datetime]
    last_seen:        Optional[datetime]


@dataclass
class PcStats:
    """Per-PC summary counts, pre-computed so report.py just reads them."""

    pc_name:           str
    total_raw:         int = 0
    total_unique:      int = 0
    certified:         int = 0   # has publisher
    hash_only:         int = 0   # no publisher, has sha256
    unknown:           int = 0   # no publisher, no sha256
    microsoft:         int = 0
    enforcement_blocks: int = 0  # EventID 3033 or 3034


@dataclass
class ParsedData:
    """
    Everything report.py needs.  log_parser.parse_logs() returns this.

    All counts are pre-computed — report.py must not re-count or re-loop.

    Fields
    ------
    entries
        Globally deduplicated list of LogEntry objects, one per unique
        (filepath, sha256) pair across ALL PCs.

    pc_stats
        Per-PC summary counts, dict keyed by pc_name.

    global_stats
        Aggregate counts across all PCs.

    warnings
        Data quality warnings (missing columns, NT volume mapping used, etc.)
        Displayed at the top of the HTML report and in the terminal.

    pc_names
        Sorted list of all PC names (natural order: PC-1, PC-2, … PC-10).

    all_extensions
        Set of all file extensions seen, for the extension filter pills.

    generated_at
        When parse_logs() was called — stamped into the report.
    """

    entries:        list[LogEntry]          = field(default_factory=list)
    pc_stats:       dict[str, PcStats]      = field(default_factory=dict)
    global_stats:   dict[str, int]          = field(default_factory=dict)
    warnings:       list[str]               = field(default_factory=list)
    pc_names:       list[str]               = field(default_factory=list)
    all_extensions: set[str]               = field(default_factory=set)
    generated_at:   datetime               = field(default_factory=datetime.now)
    # {collection_ts: [pc_name, ...]} — one entry per unique run timestamp.
    # Derived from earliest event timestamp in the CSV content.
    collection_runs: dict[str, list[str]]  = field(default_factory=dict)
    # Set of all unique policy names found across all logs — for filter pills.
    all_policies: set[str]               = field(default_factory=set)


# ─────────────────────────────────────────────────────────────────────────────
# COLUMN DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_columns(headers: list[str]) -> dict[str, str]:
    """
    Map canonical field names to the actual column names in a CSV.

    Short aliases (≤ 5 chars) are exact-matched to avoid "id" matching
    inside "leveldisplayname".  Longer aliases use case-insensitive substring.
    """
    header_lower = {h.lower().strip(): h for h in headers}
    mapping: dict[str, str] = {}

    for field_name, aliases in COL_ALIASES.items():
        for alias in aliases:
            a_low = alias.lower()
            exact = len(a_low) <= 5
            for h_low, h_orig in header_lower.items():
                if (h_low == a_low) if exact else (a_low in h_low):
                    mapping[field_name] = h_orig
                    break
            if field_name in mapping:
                break

    return mapping


# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────

def classify(filepath: str, publisher: str, sha256: str) -> str:
    """
    Assign a security category to a file.

    Returns one of:
      "microsoft"       — signed by Microsoft Corporation
      "publisher_signed"— signed by any other publisher
      "system_unsigned" — unsigned binary in a Windows system path
      "hash_only"       — unsigned but we have a SHA256 for a hash rule
      "unknown"         — no publisher AND no hash (no rule can be written)
    """
    pub  = publisher.lower()
    path = filepath.lower()

    if any(ms in pub for ms in MICROSOFT_PUBLISHERS):
        return "microsoft"
    if any(path.startswith(sp) for sp in SYSTEM_PATHS) and not pub:
        return "system_unsigned"
    if pub:
        return "publisher_signed"
    if sha256:
        return "hash_only"
    return "unknown"


def detect_policy_type(policyguid: str) -> str:
    """Return "windows" if the GUID matches a known Windows inbox policy."""
    guid = policyguid.strip().upper()
    if guid and not guid.startswith("{"):
        guid = "{" + guid + "}"
    return "windows" if guid in WINDOWS_POLICY_GUIDS else "custom"


# ─────────────────────────────────────────────────────────────────────────────
# RAW FIELD EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def _get(row: dict, col_map: dict[str, str], field_name: str) -> str:
    """
    Safe field extraction from a CSV row dict.

    Sanitises known garbage values from broken legacy PowerShell exports:
      - "System.Object[]"  →  ""
      - Pure small integers in publisher/hash fields  →  ""
    """
    col = col_map.get(field_name)
    if not col:
        return ""
    val = str(row.get(col, "") or "").strip()
    if val in ("System.Object[]", "System.Object", ""):
        return ""
    if field_name in ("publisher", "sha256", "processname", "policyname"):
        if val.isdigit() and len(val) < 10:
            return ""
    return val


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def parse_logs(csv_files: list[Path]) -> ParsedData:
    """
    Parse a list of WDAC log CSV files and return a ``ParsedData`` object.

    This is the only public function in this module.  Everything else is
    an implementation detail.

    Parameters
    ----------
    csv_files
        Paths to CSV files in logs/.  Typically provided by core/main.py
        after scanning the logs/ directory.

    Returns
    -------
    ParsedData
        Ready to pass to report/report.py.  All counts pre-computed.
    """
    result         = ParsedData()
    # global dedup: (filepath.lower(), sha256.lower()) → LogEntry
    global_map:    dict[tuple[str, str], LogEntry] = {}
    pc_raw_counts: dict[str, int] = defaultdict(int)

    for csv_path in csv_files:
        _parse_single_csv(csv_path, global_map, pc_raw_counts, result.warnings,
                          result.collection_runs)

    # ── Finalise entries ──────────────────────────────────────────────────────
    result.entries = list(global_map.values())

    # ── Collect unique policy names for filter pills ───────────────────────────
    result.all_policies = {
        e.policyname for e in result.entries
        if e.policyname and e.policyname not in ("—", "", "Default")
    }

    # ── Build pc_names (natural sort) ─────────────────────────────────────────
    all_pcs = set()
    for entry in result.entries:
        all_pcs.update(entry.pcs)
    result.pc_names = sorted(all_pcs, key=natural_sort_key)

    # ── All extensions (for filter pills in report) ───────────────────────────
    result.all_extensions = {e.extension for e in result.entries if e.extension}

    # ── Per-PC stats ──────────────────────────────────────────────────────────
    for pc in result.pc_names:
        stats = PcStats(pc_name=pc, total_raw=pc_raw_counts.get(pc, 0))
        for entry in result.entries:
            if pc not in entry.pcs:
                continue
            stats.total_unique += 1
            if entry.category == "microsoft":
                stats.microsoft += 1
            elif entry.category == "publisher_signed":
                stats.certified += 1
            elif entry.category == "hash_only":
                stats.hash_only += 1
            elif entry.category == "unknown":
                stats.unknown += 1
            if entry.eventid in ("3033", "3034"):
                stats.enforcement_blocks += 1
        result.pc_stats[pc] = stats

    # ── Global stats ──────────────────────────────────────────────────────────
    result.global_stats = {
        "total_unique":       len(result.entries),
        "certified":          sum(1 for e in result.entries if e.publisher),
        "hash_only":          sum(1 for e in result.entries if not e.publisher and e.sha256),
        "unknown":            sum(1 for e in result.entries if not e.publisher and not e.sha256),
        "microsoft":          sum(1 for e in result.entries if e.category == "microsoft"),
        "enforcement_blocks": sum(1 for e in result.entries if e.eventid in ("3033", "3034")),
        "pc_count":           len(result.pc_names),
    }

    return result


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL: SINGLE CSV PARSE
# ─────────────────────────────────────────────────────────────────────────────

def _collection_ts_from_path(csv_path: Path, earliest_event_dt: Optional[datetime]) -> str:
    """
    Return a collection timestamp string for grouping runs in the report.

    Filenames no longer contain a timestamp (e.g. ``PC-7.csv``), so we
    always derive the timestamp from the earliest event datetime in the
    file content.  Falls back to "unknown" if the file has no parseable
    events.
    """
    if earliest_event_dt:
        return earliest_event_dt.strftime("%Y-%m-%dT%H:%M")
    return "unknown"


def _parse_single_csv(
    csv_path:        Path,
    global_map:      dict[tuple[str, str], LogEntry],
    pc_raw_counts:   dict[str, int],
    warnings:        list[str],
    collection_runs: dict[str, list[str]],
) -> None:
    """
    Parse one CSV file and merge its events into global_map.

    Mutates global_map, pc_raw_counts, and collection_runs in-place.
    Appends data-quality warnings to the warnings list.
    """
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            import csv as _csv
            dialect = _csv.Sniffer().sniff(sample)
        except Exception:
            import csv as _csv
            dialect = _csv.excel

        reader  = csv.DictReader(f, dialect=dialect)
        headers = list(reader.fieldnames or [])
        col_map = detect_columns(headers)

        if not col_map.get("filepath"):
            warnings.append(
                f"⚠ [{csv_path.name}] No FilePath column detected — check CSV headers."
            )
            return

        if not col_map.get("machinename"):
            warnings.append(
                f"⚠ [{csv_path.name}] No MachineName column — PC name will be 'Unknown'."
            )

        _local_pcs: set[str] = set()   # PCs seen only in this file
        _local_dts: list[datetime] = []  # event timestamps only in this file
        _sentinel_ts: Optional[str] = None  # collection timestamp from sentinel row

        for i, row in enumerate(reader):
            # ── Sentinel row (metadata, not an event) ────────────────────────
            eid = _get(row, col_map, "eventid")
            if eid == "__collection_ts__":
                _sentinel_ts = _get(row, col_map, "timecreated")
                pc_from_sentinel = _get(row, col_map, "machinename")
                if pc_from_sentinel:
                    _local_pcs.add(pc_from_sentinel)
                continue

            if eid and eid not in WDAC_EVENT_IDS:
                continue

            filepath     = nt_to_win32_path(_get(row, col_map, "filepath"))
            publisher    = _get(row, col_map, "publisher")
            issuer       = _get(row, col_map, "issuer")
            sha256       = flat_hash_to_hex(_get(row, col_map, "sha256"))
            sha1         = flat_hash_to_hex(_get(row, col_map, "sha1"))
            timecreated  = _get(row, col_map, "timecreated")
            processname  = _get(row, col_map, "processname")
            policyname   = _get(row, col_map, "policyname")
            policyguid   = _get(row, col_map, "policyguid")
            origname     = _get(row, col_map, "originalfilename")

            # PC name from content — never from filename
            pc_name = _get(row, col_map, "machinename") or "Unknown"

            if not filepath:
                continue

            pc_raw_counts[pc_name] += 1
            _local_pcs.add(pc_name)

            fp_path   = Path(filepath)
            dt        = parse_timestamp(timecreated)
            if dt:
                _local_dts.append(dt)
            dedup_key = (filepath.lower(), sha256.lower())

            if dedup_key not in global_map:
                global_map[dedup_key] = LogEntry(
                    filepath         = filepath,
                    filename         = fp_path.name,
                    extension        = fp_path.suffix.lower(),
                    publisher        = publisher,
                    sha256           = sha256,
                    sha1             = sha1,
                    eventid          = eid,
                    timecreated      = timecreated,
                    dt               = dt,
                    processname      = processname,
                    policyname       = policyname,
                    policyguid       = policyguid,
                    policy_type      = detect_policy_type(policyguid),
                    originalfilename = origname,
                    issuer           = issuer,
                    category         = classify(filepath, publisher, sha256),
                    pcs              = [pc_name],
                    pc_hits          = {pc_name: 1},
                    total_hits       = 1,
                    all_timestamps   = [(dt, pc_name, 1)] if dt else [],
                    first_seen       = dt,
                    last_seen        = dt,
                )
            else:
                entry = global_map[dedup_key]
                entry.total_hits += 1
                if pc_name not in entry.pc_hits:
                    entry.pcs.append(pc_name)
                    entry.pc_hits[pc_name] = 1
                else:
                    entry.pc_hits[pc_name] += 1

                if dt:
                    entry.all_timestamps.append((dt, pc_name, 1))
                    if not entry.first_seen or dt < entry.first_seen:
                        entry.first_seen = dt
                    if not entry.last_seen or dt > entry.last_seen:
                        entry.last_seen = dt

    # ── Register this CSV's collection timestamp ──────────────────────────────
    # Prefer the sentinel row timestamp (= when --collect actually ran).
    # Fall back to earliest event datetime only for legacy CSVs without sentinel.
    if _sentinel_ts:
        coll_ts = _sentinel_ts
    else:
        earliest_dt: Optional[datetime] = None
        if _local_dts:
            earliest_dt = min(_local_dts)
        coll_ts = _collection_ts_from_path(csv_path, earliest_dt)

    # Group PCs by collection timestamp
    if coll_ts not in collection_runs:
        collection_runs[coll_ts] = []
    for pc in _local_pcs:
        if pc not in collection_runs[coll_ts]:
            collection_runs[coll_ts].append(pc)
