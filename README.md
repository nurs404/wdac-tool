# WDAC Multi-Tool | WARNING currently it is early stage with many bugs, not all features are implemented/working !!!

> **Automated audit log collection and analysis for Windows Defender Application Control across classroom small-fleet Windows environments.**

---

## What is WDAC?

**Windows Defender Application Control (WDAC)** is a built-in Windows security utility that enforces strict control over which executables are permitted to run on a machine. It operates at the kernel level — meaning it acts before any user space process can intercept it!

When policy is deployed in **audit mode**, WDAC does not block anything. Instead, it silently logs every executable that violates policy. These audit logs are the foundation for building a production ready allowlist: you collect logs, review them, and sign off on what's allowed or not BEFORE you could switch to enforcement and fuck up something, avoiding acidents!

The problem is that doing this at scale is genuinely painful. You have to access each machine 1 by 1, dig through Event Viewer, export logs manually, parse XML, and try to make sense of thousands of individual file-level events with no tooling to help you.
THIS PROJECT FIXES THAT!

---

## What this tool does

WDAC Multi-Tool automates the entire audit workflow in a single command:

1. **Connects** to each classroom PC over WinRM (Windows Remote Management) in parallel
2. **Queries** the `Microsoft-Windows-CodeIntegrity/Operational` event log directly — no files to copy, no manual exports
3. **Correlates** signature events (Event ID 3089) with other events (3076/3077/3033/3034) to recover publisher and certificate information
4. **Writes** one timestamped CSV per machine to a local `logs/` folder
5. **Parses** and deduplicates all entries across all machines — one record per unique `(filepath, SHA256)` pair
6. **Generates** a self-contained interactive HTML report you can open in any browser that also has many useful filters

The report gives you a full picture of your fleet: what's and where running, who launched it, who signed it, which machines it appeared on, when and how many times, whether WDAC can write a rule for it (publisher rule, hash rule, or unknown). and etc

---

## Requirements

- Python 3.10+
- `pywinrm` (`pip install pywinrm`)
- Target PCs must have WinRM enabled (see [Setup](#setup))
- WDAC policy deployed in audit mode on target machines

---

## Setup | WARNING likely bugged #to-do create python script that would setup everything

### Enable WinRM on target PCs

Run once on each target machine (or via GPO):

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
```

### Install dependencies

```bash
pip install pywinrm
```

### Clone and run

```bash
git clone https://github.com/nurs404/wdac-multi-tool.git
cd wdac-multi-tool
python run.py --help
```

---

## Usage #to-do implement cli controls that user can interact with (like gui but i cant implement it for now)

### Collect logs from all PCs and generate a report

```bash
python run.py --collect
```
#to-do add config file where user name, password, pc name, max-pcs, output path will be stored
You will be prompted for the local account password. Collection runs in parallel across all configured PCs. Results are written to `logs/` and a report is generated in `reports/`.

### Collect from a specific range of machines

```bash
python run.py --collect --pcs 1-10
python run.py --collect --pcs 2-5,8,11-15
```

### Re-generate the report from existing logs (no network required)

```bash
python run.py
```

### Common options

| Flag | Default | Description |
|---|---|---|
| `--collect` | `off` | Pull live logs from remote PCs before analysing |
| `--pcs` | `all` | PC range: `all`, `1-10`, `2-5,8` |
| `--max-pcs` | `25` | Highest PC number #to-do make it dynamic and warn when exceeding safe limits |
| `--days-back` | `30` | How far back to query the event log |
| `--max-events` | `5000` | Maximum events to pull per PC |
| `--username` | `user` | Local account name on target PCs |
| `--timeout` | `20` | Per-PC WinRM timeout in seconds |
| `--out` | `reports/` | Output folder for the HTML report |
| `--vol-map` | — | Override NT volume mapping, e.g. `--vol-map 3=D` #to-do add explanation |

---

## Report features

The generated HTML report is fully self-contained — no server, no dependencies, note that it doesnt update on its own.

- **Summary** — when logs collected and report created, amount of pcs/files/certified/no-cert/enforcement blocks, all at a glance
- **Filters** — filter by PC, file extension, policy name with simple pill like buttons
- **Text search** — filter by filename or full path
- **Min hits / Min PCs** — surface files that appear across multiple machines or repeatedly
- **Time range picker** — narrow events to a specific window with amazing time range filter that supports wild cards
- **Sortable table** — sort by type, last seen, file, publisher, or hit count
- **Detail panel** — per-entry: full path, calling process, publisher, SHA256, policy GUID, etc, and an activity timeline showing when and on which PCs each file was seen
- **Pagination** — handles large datasets cleanly | WARNING not tested!

---

## File classification

Each unique file is assigned one of five categories:

| Category | Meaning | WDAC rule possible? |
|---|---|---|
| **Microsoft** | Signed by Microsoft Corporation | Yes — but it could be a system component |
| **Certified** | Signed by a third-party publisher | Yes — publisher rule |
| **System** | Unsigned binary in a Windows system path | Yes — path or hash rule, but it could be a system component |
| **Hash only** | Unsigned, but SHA256 available | Yes — hash rule, but hashes may change and break policies |
| **No cert** | No publisher, no hash | Manual review required |

---

## Project structure

```
wdac-multi-tool/
├── run.py                        # Entry point
├── requirements.txt
├── core/
│   ├── functions.py              # Shared utilities (hashing, path resolution, sorting)
│   └── main.py                   # CLI parser and orchestrator
├── data/
│   ├── _ps_snippet.py            # Embedded PowerShell — runs on remote PCs
│   ├── log_parser.py             # CSV → ParsedData (dedup, classify, stats)
│   └── remote_handler.py        # WinRM collection (pywinrm, ThreadPoolExecutor)
├── report_generator/
│   └── report.py                 # Self-contained HTML report generator
├── logs/                         # Collected CSVs (one per PC, overwritten each run)
└── reports/                      # Generated HTML reports
```

---

## How collection works

The tool sends a compressed PowerShell snippet to each remote PC over WinRM. The snippet runs locally on the target, queries `Get-WinEvent` against `Microsoft-Windows-CodeIntegrity/Operational`, parses each event's XML by named field (not positional index), correlates 3089 signature events to recover publisher data, and returns compact JSON to Python over stdout. Python writes the CSV and moves on. The entire script is gzip-compressed before transmission to stay within cmd.exe's command-line length limit.

Event IDs collected:

| Event ID | Meaning |
|---|---|
| 3076 | Audit block — would have been blocked in enforcement mode |
| 3077 | Enforcement block — was blocked |
| 3033 | Enforcement block (revoked/expired signature) |
| 3034 | Audit equivalent of 3033 |
| 3089 | Signature info — correlated to above via ActivityID |

---

## Status

Early development. Tested on a fleet of up to 25 Windows 11 PCs. Contributions and issue reports welcome, hate no! ;)
