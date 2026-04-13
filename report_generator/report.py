"""
report_generator/report.py
"""

from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from core.functions import sanitize_xml, natural_sort_key
from data.log_parser import LogEntry, ParsedData

_EVENT_LABELS = {
    "3076": ("Audit log",         "audit"),
    "3077": ("Enforcement block", "enforce"),
    "3033": ("Enforcement block", "enforce"),
    "3034": ("Audit log",         "audit"),
}
_BADGES = {
    "microsoft":        '<span class="badge ms">Microsoft</span>',
    "publisher_signed": '<span class="badge pub">Certified</span>',
    "system_unsigned":  '<span class="badge sys">System</span>',
    "hash_only":        '<span class="badge hash">Hash only</span>',
    "unknown":          '<span class="badge unk">No cert</span>',
}

_SHIELD_SVG = """<svg class="logo-svg" width="36" height="38" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 385.84 401.32"><defs><linearGradient id="msd-a" x1="564.08" y1="144.16" x2="399.95" y2="428.44" gradientTransform="matrix(1, 0, 0, -1, 0, 770)" gradientUnits="userSpaceOnUse"><stop offset="0.37" stop-color="#114a8b"/><stop offset="1" stop-color="#0c59a4"/></linearGradient><linearGradient id="msd-b" x1="402.18" y1="195.84" x2="262.61" y2="437.59" gradientTransform="matrix(1, 0, 0, -1, 0, 770)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#0669bc"/><stop offset="1" stop-color="#0078d4"/></linearGradient><linearGradient id="msd-c" x1="528.83" y1="360.36" x2="390.83" y2="599.36" gradientTransform="matrix(1, 0, 0, -1, 0, 770)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#0078d4"/><stop offset="1" stop-color="#1493df"/></linearGradient><linearGradient id="msd-d" x1="353.62" y1="380.7" x2="215.62" y2="619.71" gradientTransform="matrix(1, 0, 0, -1, 0, 770)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#28afea"/><stop offset="0.74" stop-color="#3ccbf4"/></linearGradient></defs><path d="M384,584.66a13.55,13.55,0,0,0,6.72-1.76C490.33,525.46,556.76,461,573,376.28q.42-2.19.79-4.38L370.69,358.45Z" transform="translate(-191.08 -183.34)" style="fill:url(#msd-a)"/><path d="M377.27,582.9a13.54,13.54,0,0,0,6.72,1.76V358.44L194.23,371.89q.38,2.2.79,4.38C211.24,461,277.66,525.45,377.27,582.89Z" transform="translate(-191.08 -183.34)" style="fill:url(#msd-b)"/><path d="M576.92,249a13.1,13.1,0,0,0-12.74-13.15c-60.25-1.24-81.56-11.65-111.27-31.7A117.71,117.71,0,0,0,384,183.36l-20,188.4H573.79a213,213,0,0,0,3.12-36Z" transform="translate(-191.08 -183.34)" style="fill:url(#msd-c)"/><path d="M384,183.36a117.71,117.71,0,0,0-68.9,20.79c-29.72,20.06-51,30.47-111.27,31.7A13.1,13.1,0,0,0,191.08,249v86.8a213,213,0,0,0,3.12,36H384Z" transform="translate(-191.08 -183.34)" style="fill:url(#msd-d)"/></svg>"""


def generate_report(parsed: ParsedData, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts       = parsed.generated_at.strftime("%Y-%m-%d_%H%M")
    out_path = out_dir / f"report_{ts}.html"
    out_path.write_text(_build_html(parsed), encoding="utf-8")
    return out_path


def _build_html(parsed: ParsedData) -> str:
    gs        = parsed.global_stats
    generated = parsed.generated_at.strftime("%d/%m/%Y %H:%M")
    pc_count  = gs.get("pc_count", 0)

    coll_html = _build_collection_runs(parsed.collection_runs, generated, pc_count)

    pc_pills = '<button class="pill active" onclick="filterPC(\'all\')">All</button>\n'
    for pc in parsed.pc_names:
        e = sanitize_xml(pc).replace("'", "\\'")
        pc_pills += f'<button class="pill" onclick="filterPC(\'{e}\')">{sanitize_xml(pc)}</button>\n'

    ext_pills = '<button class="pill active" onclick="filterExt(\'all\')">All</button>\n'
    for ext in sorted(parsed.all_extensions):
        e = sanitize_xml(ext)
        ext_pills += f'<button class="pill" onclick="toggleExt(\'{e}\')">{e or "(none)"}</button>\n'

    pol_pills = '<button class="pill active" onclick="filterPol(\'all\')">All</button>\n'
    for pol in sorted(parsed.all_policies):
        e = sanitize_xml(pol)
        pol_pills += f'<button class="pill" onclick="togglePol(\'{e.replace(chr(39), chr(92)+chr(39))}\')">{e}</button>\n'

    warn_html = ""
    if parsed.warnings:
        items = "".join(f"<li>{sanitize_xml(w)}</li>" for w in parsed.warnings)
        warn_html = f'<div class="warn-bar"><span class="warn-icon">⚠</span><ul>{items}</ul></div>'

    sorted_entries = sorted(
        parsed.entries,
        key=lambda e: e.last_seen or e.dt or datetime.min,
        reverse=True,
    )
    all_rows = "\n".join(_gen_row(e, i) for i, e in enumerate(sorted_entries))

    max_hits = max((e.total_hits for e in parsed.entries), default=1)

    all_dts = [e.last_seen or e.dt for e in parsed.entries if (e.last_seen or e.dt)]
    all_dts += [e.first_seen for e in parsed.entries if e.first_seen]
    log_from_iso = min(all_dts).isoformat() if all_dts else ""
    log_to_iso   = max(all_dts).isoformat() if all_dts else ""

    total  = gs.get("total_unique", 0)
    cert   = gs.get("certified", 0)
    honly  = gs.get("hash_only", 0)
    nocert = gs.get("unknown", 0)
    blocks = gs.get("enforcement_blocks", 0)
    pct    = lambda n: int(n / max(total, 1) * 100)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WDAC Report — {generated}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
{_css()}
</head>
<body>
<div class="shell">

  <header class="site-header">
    <div class="header-left">
      <div class="logo-block">
        {_SHIELD_SVG}
        <div>
          <h1>WDAC <span class="accent">Audit</span></h1>
        </div>
      </div>
    </div>
    <div class="header-right">{coll_html}</div>
  </header>

  {warn_html}

  <div class="cards">
    <div class="card card--total active" id="card-all" onclick="clearCat()">
      <div class="card-num">{total}</div><div class="card-lbl">Total unique</div>
      <div class="card-bar" style="width:100%"></div>
    </div>
    <div class="card card--cert" id="card-publishersigned" onclick="filterCat('publisher_signed')">
      <div class="card-num">{cert}</div><div class="card-lbl">Certified</div>
      <div class="card-bar" style="width:{pct(cert)}%"></div>
    </div>
    <div class="card card--future" id="card-hashonly">
      <div class="card-num card-num--dim">—</div><div class="card-lbl">Reserved</div>
      <div class="card-bar"></div>
    </div>
    <div class="card card--nocert" id="card-unknown" onclick="filterCat('unknown')">
      <div class="card-num">{nocert}</div><div class="card-lbl">No cert</div>
      <div class="card-bar" style="width:{pct(nocert)}%"></div>
    </div>
    <div class="card card--block" id="card-blocks" onclick="filterSysBlocks()">
      <div class="card-num">{blocks}</div><div class="card-lbl">Enforcement blocks</div>
      <div class="card-bar" style="width:{pct(blocks)}%"></div>
    </div>
  </div>

  <div class="filter-panel">

    <div class="frow">
      <span class="frow-label">PC</span>
      <div class="pills" id="pc-pills">{pc_pills}</div>
    </div>
    <div class="frow">
      <span class="frow-label">EXT</span>
      <div class="pills" id="ext-pills">{ext_pills}</div>
    </div>
    <div class="frow">
      <span class="frow-label">Policy</span>
      <div class="pills" id="pol-pills">{pol_pills}</div>
    </div>

    <div class="fdivider"></div>

    <div class="frow frow--wrap">
      <div class="finput-group">
        <label class="finput-label">Filename</label>
        <input class="finput" type="text" id="fname-search" placeholder="Search…" oninput="applyFilters()">
      </div>
      <div class="finput-group">
        <label class="finput-label">Path</label>
        <input class="finput" type="text" id="path-search" placeholder="Search…" oninput="applyFilters()">
      </div>
      <div class="finput-group finput-group--sm">
        <label class="finput-label">Min hits</label>
        <div class="numkey-wrap">
          <input class="finput finput--numkey" id="min-hits" value="1"
                 data-max="{max_hits}"
                 onkeydown="numKey(event,this,1,{max_hits})" oninput="numSanitize(this,1,{max_hits})"
                 onblur="numCommit(this,1,{max_hits},'applyFilters')" inputmode="numeric">
          <div class="nk-arrows">
            <div class="nk-arrow" onclick="numStep('min-hits',1,{max_hits},1)" title="Increase">▲</div>
            <div class="nk-arrow" onclick="numStep('min-hits',1,{max_hits},-1)" title="Decrease">▼</div>
          </div>
        </div>
      </div>
      <div class="finput-group finput-group--sm">
        <label class="finput-label">Min PCs</label>
        <div class="numkey-wrap">
          <input class="finput finput--numkey" id="min-pcs" value="1"
                 data-max="{pc_count}"
                 onkeydown="numKey(event,this,1,{pc_count})" oninput="numSanitize(this,1,{pc_count})"
                 onblur="numCommit(this,1,{pc_count},'applyFilters')" inputmode="numeric">
          <div class="nk-arrows">
            <div class="nk-arrow" onclick="numStep('min-pcs',1,{pc_count},1)" title="Increase">▲</div>
            <div class="nk-arrow" onclick="numStep('min-pcs',1,{pc_count},-1)" title="Decrease">▼</div>
          </div>
        </div>
      </div>
      <div class="finput-group finput-group--sm">
        <label class="finput-label">&nbsp;</label>
        <button class="fbtn fbtn--reset" onclick="resetFilters()" style="height:28px">Reset filters</button>
      </div>
    </div>

    <div class="frow frow--dt" id="dt-row" data-log-from="{log_from_iso}" data-log-to="{log_to_iso}">
      <div class="dt-block">
        <span class="finput-label">Time range</span>
        <div class="dt-row">
          <div class="dt-mask-wrap" id="dt-from-wrap" onclick="dtWrapClick(event,'from')">
            <span class="dt-seg" id="ds-from-hh" onclick="dtSegClick(event,'from',0)"><span class="dt-typed"></span><span class="dt-ph">hh</span></span><span class="dt-sep">:</span><span class="dt-seg" id="ds-from-mm" onclick="dtSegClick(event,'from',1)"><span class="dt-typed"></span><span class="dt-ph">mm</span></span><span class="dt-spc"> </span><span class="dt-seg" id="ds-from-dd" onclick="dtSegClick(event,'from',2)"><span class="dt-typed"></span><span class="dt-ph">dd</span></span><span class="dt-sep">/</span><span class="dt-seg" id="ds-from-mo" onclick="dtSegClick(event,'from',3)"><span class="dt-typed"></span><span class="dt-ph">mm</span></span><span class="dt-sep">/</span><span class="dt-seg" id="ds-from-yr" onclick="dtSegClick(event,'from',4)"><span class="dt-typed"></span><span class="dt-ph">yyyy</span></span>
            <input class="dt-hidden" id="dt-from" type="text" inputmode="numeric"
                   onkeydown="dtKey(event,'from')" onfocus="dtActivate('from')" onblur="dtBlur('from')">
          </div>
          <span class="dt-arrow">→</span>
          <div class="dt-mask-wrap" id="dt-to-wrap" onclick="dtWrapClick(event,'to')">
            <span class="dt-seg" id="ds-to-hh" onclick="dtSegClick(event,'to',0)"><span class="dt-typed"></span><span class="dt-ph">hh</span></span><span class="dt-sep">:</span><span class="dt-seg" id="ds-to-mm" onclick="dtSegClick(event,'to',1)"><span class="dt-typed"></span><span class="dt-ph">mm</span></span><span class="dt-spc"> </span><span class="dt-seg" id="ds-to-dd" onclick="dtSegClick(event,'to',2)"><span class="dt-typed"></span><span class="dt-ph">dd</span></span><span class="dt-sep">/</span><span class="dt-seg" id="ds-to-mo" onclick="dtSegClick(event,'to',3)"><span class="dt-typed"></span><span class="dt-ph">mm</span></span><span class="dt-sep">/</span><span class="dt-seg" id="ds-to-yr" onclick="dtSegClick(event,'to',4)"><span class="dt-typed"></span><span class="dt-ph">yyyy</span></span>
            <input class="dt-hidden" id="dt-to" type="text" inputmode="numeric"
                   onkeydown="dtKey(event,'to')" onfocus="dtActivate('to')" onblur="dtBlur('to')">
          </div>
          <button class="fbtn fbtn--clr" onclick="clearDT()">✕</button>
        </div>
      </div>
    </div>

  </div>

  <div class="table-wrap">
    <div class="table-toolbar">
      <span class="toolbar-title">Flagged files</span>
      <span class="entry-count" id="result-count">{total} entries</span>
    </div>
    <table class="main-table">
      <thead>
        <tr>
          <th class="col-badge" onclick="sortTable('type')">Type <span class="sarr"></span></th>
          <th class="col-time" onclick="sortTable('time')">Last seen <span class="sarr"></span></th>
          <th class="col-file" onclick="sortTable('file')">File <span class="sarr"></span></th>
          <th class="col-pub" onclick="sortTable('publisher')">Publisher <span class="sarr"></span></th>
          <th class="col-hits" onclick="sortTable('hits')">Hits <span class="sarr"></span></th>
          <th class="col-exp"></th>
        </tr>
      </thead>
      <tbody id="table-body">{all_rows}</tbody>
    </table>
    <div class="empty-state" id="empty-state">No matching entries</div>
  </div>

  <div class="pagination" id="pagination" style="display:none">
    <button onclick="goToPage(1)" id="btn-first">⟨⟨</button>
    <button onclick="goToPage(currentPage-1)" id="btn-prev">⟨</button>
    <span class="page-info">Page <strong id="current-page">1</strong> / <strong id="total-pages">1</strong></span>
    <button onclick="goToPage(currentPage+1)" id="btn-next">⟩</button>
    <button onclick="goToPage(totalPages)" id="btn-last">⟩⟩</button>
    <select onchange="changePageSize(this)">
      <option value="1000" selected>1000/page</option>
      <option value="2500">2500/page</option>
      <option value="99999">All</option>
    </select>
  </div>

</div>
{_scripts()}
</body></html>"""


def _build_collection_runs(runs: dict[str, list[str]], generated: str, pc_count: int) -> str:
    if not runs:
        return (
            f'<div class="coll-wrap">'
            f'<button class="coll-summary" style="cursor:default">'
            f'<span class="coll-meta">Report generated <span class="coll-meta-val">{generated}</span></span>'
            f'<span class="coll-pipe">|</span>'
            f'<span class="coll-meta">Logs collected from <span class="coll-meta-val">{pc_count} PC{"s" if pc_count != 1 else ""}</span></span>'
            f'</button></div>'
        )

    sorted_keys = sorted(runs.keys())
    n = len(sorted_keys)

    try:
        first_dt = datetime.fromisoformat(sorted_keys[0])
        first_str = first_dt.strftime("%d/%m/%Y %H:%M")
    except ValueError:
        first_str = sorted_keys[0]
    try:
        last_dt = datetime.fromisoformat(sorted_keys[-1])
        last_str = last_dt.strftime("%d/%m/%Y %H:%M")
    except ValueError:
        last_str = sorted_keys[-1]

    rows = []
    for ts_key in sorted_keys:
        pcs = sorted(runs[ts_key], key=natural_sort_key)
        try:
            dt = datetime.fromisoformat(ts_key)
            ts_display = dt.strftime("%d/%m/%Y %H:%M")
        except ValueError:
            ts_display = ts_key
        pc_str = _compact_pc_list(pcs)
        rows.append(
            f'<div class="coll-run">'
            f'<span class="coll-ts">{ts_display}</span>'
            f'<span class="coll-sep">·</span>'
            f'<span class="coll-pcs">{sanitize_xml(pc_str)}</span>'
            f'</div>'
        )

    detail_html = "".join(rows)
    pc_label = f"{pc_count} PC" + ("s" if pc_count != 1 else "")
    range_str = first_str if n==1 else f"{first_str} → {last_str}"
    return (
        f'<div class="coll-wrap">'
        f'<button class="coll-summary" onclick="toggleColl(this)" title="Show individual log runs">'
        f'<span class="coll-meta">Report generated <span class="coll-meta-val">{generated}</span></span>'
        f'<span class="coll-pipe">|</span>'
        f'<span class="coll-meta">Logs collected from <span class="coll-meta-val">{sanitize_xml(pc_label)}</span></span>'
        f'<span class="coll-pipe">|</span>'
        f'<span class="coll-meta-val coll-range">{sanitize_xml(range_str)}</span>'
        f'<span class="coll-chevron">▾</span>'
        f'</button>'
        f'<div class="coll-detail hidden">{detail_html}</div>'
        f'</div>'
    )


def _compact_pc_list(pcs: list[str]) -> str:
    """Compress PC name list into range notation, e.g. PC-1,PC-2,PC-3 -> PC-1–3.

    Groups by prefix, compresses consecutive numbers within each group.
    Deduplicates same (prefix, number) pairs to guard against case mismatches.
    No regex used to avoid edit-tool escaping issues.
    """
    if not pcs:
        return ""
    from collections import defaultdict
    groups: dict = defaultdict(list)
    no_num = []
    for pc in pcs:
        i = len(pc)
        while i > 0 and pc[i - 1].isdigit():
            i -= 1
        if i < len(pc):
            groups[pc[:i]].append(int(pc[i:]))
        else:
            no_num.append(pc)
    parts = []
    for prefix in sorted(groups.keys()):
        nums = sorted(set(groups[prefix]))
        rstart = rend = nums[0]
        for n in nums[1:]:
            if n == rend + 1:
                rend = n
            else:
                parts.append(f"{prefix}{rstart}" if rstart == rend else f"{prefix}{rstart}–{rend}")
                rstart = rend = n
        parts.append(f"{prefix}{rstart}" if rstart == rend else f"{prefix}{rstart}–{rend}")
    return ", ".join(parts + sorted(no_num))


def _fmt(dt: datetime | None) -> tuple[str, str, str]:
    if dt:
        return dt.strftime("%d/%m %H:%M"), dt.isoformat(), dt.strftime("%d/%m/%Y %H:%M:%S")
    return "—", "", "—"


def _gen_row(e: LogEntry, idx: int) -> str:
    cat    = e.category
    badge  = _BADGES.get(cat, _BADGES["unknown"])
    fpath  = e.filepath
    fname  = e.filename or Path(fpath).name or fpath
    pub    = e.publisher or "—"
    sha256 = e.sha256 or "—"
    proc   = e.processname or "—"
    eid    = e.eventid
    ptype  = e.policy_type
    pname  = e.policyname or "—"
    pguid  = e.policyguid or "—"
    orig   = e.originalfilename or "—"
    pc_cnt = len(e.pcs)
    total  = e.total_hits

    elabel, eclass = _EVENT_LABELS.get(eid, ("Unknown", "unknown"))
    disp, iso, _   = _fmt(e.last_seen or e.dt)

    pc_list   = ",".join(sorted(e.pcs, key=natural_sort_key))
    pc_hits_j = json.dumps(e.pc_hits).replace('"', '&quot;')
    sorted_ts = sorted(e.all_timestamps, key=lambda x: x[0], reverse=True)
    ts_j      = json.dumps([[t.isoformat(), pc, hits] for t, pc, hits in sorted_ts]).replace('"', '&quot;')

    row_cls = "row"
    if cat == "unknown": row_cls += " row--nocert"
    if eid in ("3033", "3077"): row_cls += " row--block"

    pbadge = f'<span class="policy-badge policy-{ptype}">{ptype}</span>'
    row_id_for_chips = f"r{idx}"
    chips  = "".join(
        f'<span class="pc-chip" data-pc="{sanitize_xml(pc)}" onclick="tlChipClick(this,\'{row_id_for_chips}\')" title="Filter timeline to this PC">'
        f'<span class="pc-chip__name">{sanitize_xml(pc)}</span>'
        f'<span class="pc-chip__hits">{hits}</span></span>'
        for pc, hits in sorted(e.pc_hits.items(), key=lambda x: natural_sort_key(x[0]))
    )
    all_chip = (
        f'<span class="pc-chip pc-chip--all tl-active" data-pc="all" '
        f'onclick="tlChipClick(this,\'{row_id_for_chips}\')" title="Show all PCs">'
        f'<span class="pc-chip__name">All</span></span>'
    )
    pc_summary = (
        f'<div class="pc-summary">Found on <strong>{pc_cnt}</strong> PC'
        f'{"s" if pc_cnt != 1 else ""} · <strong>{total}</strong> hits</div>'
        f'<div class="pc-chips">{all_chip}{chips}</div>'
    )

    row_id = f"r{idx}"
    fn_esc = sanitize_xml(fname).replace("'", "\\'")

    main = f"""\
    <tr class="{row_cls}" id="{row_id}"
      data-pc-list="{sanitize_xml(pc_list)}"
      data-pc-hits="{pc_hits_j}"
      data-all-timestamps="{ts_j}"
      data-total-hits="{total}"
      data-pc-count="{pc_cnt}"
      data-ext="{sanitize_xml(e.extension)}"
      data-timestamp="{iso}"
      data-filename="{sanitize_xml(fname.lower())}"
      data-path="{sanitize_xml(fpath.lower())}"
      data-cat="{cat}"
      data-policy="{sanitize_xml(pname)}"
      data-eventid="{eid}"
      onclick="toggle('{row_id}')" style="cursor:pointer">
      <td class="col-badge">{badge}</td>
      <td class="col-time mono">{disp}</td>
      <td class="col-file">
        <span class="fname">{sanitize_xml(fname)}</span>
        <span class="fpath">{sanitize_xml(fpath)}</span>
      </td>
      <td class="col-pub">{sanitize_xml(pub) if pub != "—" else '<span class="dim">—</span>'}</td>
      <td class="col-hits"><span class="hit-pill">{total}</span></td>
      <td class="col-exp"><span class="exp-arrow" id="arr-{row_id}">▾</span></td>
    </tr>"""

    detail = f"""\
    <tr class="detail hidden" id="{row_id}-d">
      <td colspan="6">
        <div class="detail-panel">
          <div class="dp-actions">
            <span class="ev-badge ev-{eclass} dp-event-badge">{eid} — {elabel}</span>
            <button class="dp-btn" onclick="qsearch('{fn_esc}')">🔍 Is &quot;{sanitize_xml(fname)}&quot; a system file?</button>
            <button class="dp-btn" onclick="cpHash('{sanitize_xml(sha256)}')">📋 Copy SHA256</button>
            <button class="dp-btn" data-fp="{sanitize_xml(fpath)}" onclick="cpPath(this.dataset.fp)">📁 Copy path</button>
          </div>
          <div class="dp-grid">
            <div class="dp-section">
              <div class="dp-title">File</div>
              <dl class="dp-dl">
                <dt>Full path</dt><dd><code class="dp-hi">{sanitize_xml(fpath)}</code></dd>
                <dt>Called by</dt><dd><code class="dp-hi">{sanitize_xml(proc)}</code></dd>
                <dt>Original name</dt><dd><span class="dp-hi">{sanitize_xml(orig)}</span></dd>
              </dl>
            </div>
            <div class="dp-section">
              <div class="dp-title">Policy &amp; signature</div>
              <dl class="dp-dl">
                <dt>Policy</dt><dd><span class="dp-hi">{sanitize_xml(pname)}</span> {pbadge}</dd>
                <dt>Publisher</dt><dd><span class="dp-hi">{sanitize_xml(pub)}</span></dd>
                <dt>SHA256</dt><dd><code class="mono hash-code dp-hi">{sanitize_xml(sha256)}</code></dd>
                <dt>GUID</dt><dd><code class="mono no-box dp-hi">{sanitize_xml(pguid)}</code></dd>
              </dl>
            </div>
          </div>
          <div class="dp-section">
            <div class="dp-title">PC distribution</div>
            {pc_summary}
          </div>
          <div class="dp-section">
            <div class="dp-title">Activity timeline <span class="pc-summary-hint">· click PC chips above to filter</span></div>
            <div id="tl-{row_id}" class="timeline-wrap">Loading…</div>
          </div>
        </div>
      </td>
    </tr>"""

    return main + "\n" + detail


def _css() -> str:
    return """<style>
:root{
  --bg:        hsl(0,0%,9%);
  --surface:   hsl(0,0%,12%);
  --surface2:  hsl(0,0%,14%);
  --border:    hsl(0,0%,22%);
  --border2:   hsl(0,0%,18%);
  --text:      hsl(0,0%,80%);
  --text-dim:  hsl(0,0%,45%);
  --text-hi:   hsl(0,0%,94%);
  --accent:    hsl(208,100%,42%);
  --accent-lo: hsla(208,100%,42%,0.14);
  --accent-brd:hsla(208,100%,42%,0.35);
  --cert:      hsl(142,55%,46%);
  --hash:      hsl(38,78%,50%);
  --nocert:    hsl(0,65%,56%);
  --block:     hsl(28,88%,50%);
  --hl-bg:     hsla(50,85%,50%,0.13);
  --hl-brd:    hsl(48,82%,50%);
  --mono:      'JetBrains Mono',monospace;
  --sans:      'IBM Plex Sans',sans-serif;
  --r:         6px;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.5;min-height:100vh;user-select:none;-webkit-user-select:none}
code,.mono{font-family:var(--mono)}
input,textarea,code,pre,.dp-dl dd,.selectable{user-select:text;-webkit-user-select:text}
.shell{max-width:1700px;margin:0 auto;padding:18px 22px}
.site-header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:14px;border-bottom:1px solid var(--border);margin-bottom:18px}
.header-left{display:flex;align-items:center}
.logo-block{display:flex;align-items:center;gap:12px}
.logo-svg{flex-shrink:0;filter:drop-shadow(0 0 6px hsla(208,100%,42%,.25))}
h1{font-size:18px;font-weight:600;color:var(--text-hi);letter-spacing:-.2px}
h1 .accent{color:var(--accent)}
.coll-wrap{display:flex;flex-direction:column;align-items:flex-end;gap:4px;position:relative}
.coll-summary{display:flex;align-items:center;gap:9px;background:var(--surface2);border:1px solid var(--border2);border-radius:var(--r);padding:5px 12px;font-size:11px;white-space:nowrap;cursor:pointer;transition:border-color .1s;color:var(--text);font-family:var(--sans)}
.coll-summary:hover{border-color:var(--accent)}
.coll-meta{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim)}
.coll-meta-val{font-family:var(--mono);color:var(--accent);text-transform:none;letter-spacing:0}
.coll-range{font-family:var(--mono);color:var(--accent)}
.coll-pipe{color:var(--border);font-size:12px;flex-shrink:0}
.coll-chevron{color:var(--text-dim);font-size:10px;transition:transform .15s;display:inline-block;margin-left:2px}
.coll-summary.open .coll-chevron{transform:rotate(180deg)}
.coll-detail{position:absolute;top:calc(100% + 5px);right:0;display:flex;flex-wrap:wrap;justify-content:flex-start;gap:5px;background:var(--surface);border:1px solid var(--border2);border-radius:var(--r);padding:8px 9px;min-width:100%;box-sizing:border-box;box-shadow:0 4px 14px hsla(0,0%,0%,.35);z-index:20}
.coll-detail.hidden{display:none}
.coll-run{display:flex;align-items:center;gap:6px;background:var(--surface2);border:1px solid var(--border2);border-radius:var(--r);padding:3px 9px;font-size:11px;white-space:nowrap;flex:1 0 200px;max-width:calc(33.333% - 4px);box-sizing:border-box}
.coll-ts{font-family:var(--mono);color:var(--accent);flex-shrink:0}
.coll-sep{color:var(--text-dim);flex-shrink:0;padding:0 2px}
.coll-pcs{color:var(--text-dim);flex-shrink:0}
.warn-bar{display:flex;align-items:flex-start;gap:10px;background:hsla(38,80%,40%,.08);border:1px solid hsla(38,80%,40%,.28);border-radius:var(--r);padding:9px 13px;margin-bottom:14px}
.warn-icon{color:var(--block);font-size:14px;flex-shrink:0;margin-top:1px}
.warn-bar ul{list-style:none;display:flex;flex-direction:column;gap:2px}
.warn-bar li{font-size:12px;color:var(--hash)}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:12px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:12px 14px 9px;cursor:pointer;transition:border-color .12s,background .12s;position:relative;overflow:hidden}
.card:hover{background:var(--surface2);border-color:var(--accent)}
.card.active{background:var(--surface2)}
.card--total.active{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent-brd) inset}
.card--cert.active {border-color:var(--cert);box-shadow:0 0 0 1px hsla(142,55%,46%,.35) inset}
.card--future.active{border-color:var(--border);cursor:default}
.card--nocert.active{border-color:var(--nocert);box-shadow:0 0 0 1px hsla(0,65%,56%,.35) inset}
.card--block.active {border-color:hsl(0,0%,55%);box-shadow:0 0 0 1px hsla(0,0%,55%,.4) inset}
.card--cert:hover {border-color:var(--cert)}
.card--nocert:hover{border-color:var(--nocert)}
.card--block:hover {border-color:hsl(0,0%,55%)}
.card--future{opacity:.45;cursor:default}
.card--future:hover{background:var(--surface);border-color:var(--border)}
.card-num--dim{color:var(--text-dim)}
.card-num{font-family:var(--mono);font-size:24px;font-weight:600;color:var(--text-hi);line-height:1;margin-bottom:4px}
.card-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-dim)}
.card-bar{position:absolute;bottom:0;left:0;height:2px;transition:width .4s ease}
.card--total .card-bar{background:var(--text-dim)}
.card--total.active .card-bar,.card--total:hover .card-bar{background:var(--accent)}
.card--cert  .card-bar{background:var(--cert)}
.card--future .card-bar{background:transparent}
.card--nocert .card-bar{background:var(--nocert)}
.card--block .card-bar{background:hsl(0,0%,55%)}
.filter-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:11px 13px;margin-bottom:10px;display:flex;flex-direction:column;gap:9px}
.frow{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.frow--wrap{flex-wrap:wrap}
.frow-label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-dim);min-width:42px;flex-shrink:0}
.fdivider{border-top:1px solid var(--border2);margin:1px 0}
.pills{display:flex;flex-wrap:wrap;gap:4px}
.pill{background:transparent;border:1px solid var(--border);color:var(--text-dim);font-size:11px;font-family:var(--mono);padding:3px 9px;border-radius:5px;cursor:pointer;transition:all .1s}
.pill:hover{border-color:var(--accent);color:var(--accent)}
.pill.active{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600;letter-spacing:.3px}
.finput-group{display:flex;flex-direction:column;gap:3px}
.finput-group--sm{min-width:0}
.finput-label{font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}
.finput{background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-family:var(--sans);font-size:12px;padding:5px 9px;border-radius:5px;outline:none;transition:border-color .1s;width:100%}
.finput:focus{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-lo)}
.fbtn{background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-size:11px;font-family:var(--sans);padding:5px 11px;border-radius:5px;cursor:pointer;transition:all .1s;white-space:nowrap;text-transform:uppercase;letter-spacing:.4px;height:28px;display:flex;align-items:center}
.fbtn:hover{border-color:var(--accent);color:var(--accent)}
.fbtn--reset:hover{border-color:var(--nocert);color:var(--nocert)}
.fbtn--clr{padding:4px 8px;color:var(--text-dim);border-color:transparent;background:transparent;font-size:13px;height:auto;align-self:center}
.fbtn--clr:hover{color:var(--nocert);border-color:var(--nocert)}
.frow--dt{align-items:flex-start}
.dt-block{display:flex;flex-direction:column;gap:4px}
.dt-row{display:flex;align-items:center;gap:8px}
.dt-mask-wrap{position:relative;display:inline-flex;align-items:center;background:var(--surface2);border:1px solid var(--border2);border-radius:5px;padding:5px 10px;cursor:text;font-family:var(--mono);font-size:12px;transition:border-color .1s;user-select:none;white-space:nowrap}
.dt-mask-wrap:focus-within{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-lo)}
.dt-seg{display:inline-block;padding:0 1px;border-radius:2px;color:var(--text-dim);transition:color .1s,background .1s;cursor:pointer}
.dt-seg.filled{color:var(--text-hi)}
.dt-seg.active{background:var(--accent);color:#fff;border-radius:2px}
.dt-sep{color:var(--border);padding:0 1px;pointer-events:none;user-select:none}
.dt-spc{padding:0 3px;pointer-events:none}
.dt-hidden{position:absolute;opacity:0;pointer-events:none;width:1px;height:1px;top:0;left:0;border:none;background:transparent;outline:none;font-size:1px}
.dt-arrow{color:var(--text-dim);font-size:13px;flex-shrink:0}
.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.table-toolbar{display:flex;justify-content:space-between;align-items:center;padding:9px 14px;border-bottom:1px solid var(--border)}
.toolbar-title{font-weight:600;font-size:11px;color:var(--text-hi);text-transform:uppercase;letter-spacing:.5px}
.entry-count{font-family:var(--mono);font-size:11px;font-weight:600;background:var(--accent-lo);color:var(--accent);border:1px solid var(--accent-brd);padding:2px 9px;border-radius:3px}
.main-table{width:100%;border-collapse:collapse}
thead th{background:var(--surface2);padding:7px 11px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-dim);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover,thead th.sorted{color:var(--accent)}
.sarr{font-size:11px;margin-left:4px;opacity:.6}
thead th.sorted .sarr{opacity:1;color:var(--accent)}
.col-badge{width:88px}.col-time{width:98px}.col-file{min-width:260px}
.col-pub{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.col-hits{width:58px;text-align:center}.col-exp{width:34px;text-align:center}
tbody tr.row{border-bottom:1px solid var(--border2);transition:background .08s}
tbody tr.row:hover{background:var(--surface2)}
tbody tr.row td:first-child{position:relative;padding-left:14px}
tbody tr.row td:first-child::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:transparent;transition:background .08s}
tbody tr.row--nocert td:first-child::before{background:var(--nocert)}
tbody tr.row--multi td:first-child::before{background:var(--hl-brd)}
tbody tr.row--block td:first-child::before{background:hsl(0,0%,55%)}
tbody tr.row--block.row--nocert td:first-child::before{background:hsl(0,0%,55%)}
tbody tr.row--multi{background:var(--hl-bg)!important}
tbody tr.row--multi:hover{background:hsla(50,85%,50%,0.11)!important}
tbody tr.row.hidden{display:none}
tbody tr.detail{background:var(--bg);border-bottom:1px solid var(--border);border-top:1px solid var(--border2)}
tbody tr.detail.hidden{display:none}
td{padding:8px 11px;vertical-align:middle;font-size:12px}
.fname{display:block;color:var(--text-hi);font-family:var(--mono);font-size:12px;font-weight:600}
.fpath{display:block;color:var(--text-dim);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:440px}
.hit-pill{background:var(--accent-lo);color:var(--accent);font-family:var(--mono);font-size:11px;font-weight:600;padding:2px 7px;border-radius:3px;border:1px solid var(--accent-brd)}
.exp-arrow{color:var(--text-dim);font-size:12px;display:inline-block;transition:transform .13s}
.exp-arrow.open{transform:rotate(180deg)}
.dim{color:var(--text-dim)}
.badge{display:inline-block;padding:2px 6px;border-radius:5px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;font-family:var(--mono)}
.badge.ms  {background:hsla(0,0%,50%,.12);color:var(--text-dim);border:1px solid hsla(0,0%,50%,.25)}
.badge.pub {background:hsla(142,55%,46%,.12);color:var(--cert);border:1px solid hsla(142,55%,46%,.3)}
.badge.sys {background:hsla(0,0%,50%,.10);color:var(--text-dim);border:1px solid hsla(0,0%,50%,.2)}
.badge.hash{background:hsla(38,78%,50%,.12);color:var(--hash);border:1px solid hsla(38,78%,50%,.3)}
.badge.unk {background:hsla(0,65%,56%,.12);color:var(--nocert);border:1px solid hsla(0,65%,56%,.3)}
.ev-badge{display:inline-block;padding:2px 7px;border-radius:3px;font-size:11px;font-family:var(--mono)}
.ev-audit  {background:hsla(38,78%,50%,.12);color:var(--hash);border:1px solid hsla(38,78%,50%,.25)}
.ev-enforce{background:hsla(0,65%,56%,.12);color:var(--nocert);border:1px solid hsla(0,65%,56%,.25)}
.ev-unknown{background:hsla(0,0%,50%,.10);color:var(--text-dim);border:1px solid hsla(0,0%,50%,.2)}
.policy-badge{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-family:var(--sans);font-weight:500;margin-left:5px;vertical-align:middle}
.policy-windows{background:hsla(0,0%,50%,.12);color:var(--text-dim);border:1px solid hsla(0,0%,50%,.22)}
.policy-custom {background:var(--accent-lo);color:var(--accent);border:1px solid var(--accent-brd)}
.policy-unknown{background:hsla(38,78%,50%,.12);color:var(--hash);border:1px solid hsla(38,78%,50%,.3)}
.detail-panel{padding:16px 16px 14px;display:flex;flex-direction:column;gap:14px;background:var(--bg)}
.dp-actions{display:flex;gap:7px;flex-wrap:wrap}
.dp-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);font-size:11px;font-family:var(--sans);padding:5px 11px;border-radius:5px;cursor:pointer;transition:all .12s;display:flex;align-items:center;gap:5px;letter-spacing:.1px}
.dp-btn:hover{border-color:var(--accent);color:var(--accent)}
.dp-grid{display:flex;flex-direction:column;gap:12px}
.dp-section{background:var(--surface);border:1px solid var(--border2);border-radius:6px;padding:10px 12px}
.dp-title{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--accent);margin-bottom:8px;font-weight:600}
.dp-dl{display:grid;grid-template-columns:90px 1fr;gap:4px 12px;font-size:12px}
.dp-dl dt{color:var(--text-dim);font-size:10px;text-transform:uppercase;letter-spacing:.5px;align-self:start;padding-top:2px}
.dp-dl dd{color:var(--text);word-break:break-all;min-width:0}
.dp-dl code{background:var(--surface2);color:var(--text);padding:2px 5px;border-radius:2px;word-break:break-all;white-space:pre-wrap;overflow-wrap:anywhere;display:block}
.dp-dl code.no-box{background:transparent;padding:0;border-radius:0;font-family:var(--mono);font-size:11px}
.dp-dl code.no-box.dp-hi{background:hsla(0,0%,94%,.07);padding:1px 4px;border-radius:3px}
.hash-code{font-size:10px;letter-spacing:.4px}
.dp-hi{color:var(--text-hi);background:hsla(0,0%,94%,.07);border-radius:3px;padding:1px 4px;display:inline-block}
code.dp-hi{background:hsla(0,0%,94%,.07);padding:2px 5px;border-radius:2px;display:inline;white-space:normal}
.dp-event-badge{display:inline-flex;align-items:center;padding:5px 10px;font-size:11px;border-radius:5px;font-family:var(--mono);flex-shrink:0}
.pc-summary{font-size:12px;color:var(--text);margin-bottom:6px}
.pc-summary strong{color:var(--text-hi)}
.pc-chips{display:flex;flex-wrap:wrap;gap:5px}
.pc-chip{display:inline-flex;align-items:center;gap:5px;background:var(--surface2);border:1px solid var(--border2);border-radius:5px;padding:3px 8px;cursor:pointer;transition:border-color .1s,box-shadow .1s}
.pc-chip:hover{border-color:var(--accent)}
.pc-chip.tl-active{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.pc-chip__name{font-family:var(--mono);font-size:11px;color:var(--text)}
.pc-chip__hits{background:var(--surface);color:var(--text-dim);border:1px solid var(--border);font-family:var(--mono);font-size:10px;font-weight:600;padding:1px 5px;border-radius:4px;transition:background .1s,color .1s,border-color .1s}
.pc-chip.tl-active .pc-chip__hits{background:hsla(142,55%,46%,.12);color:var(--cert);border-color:hsla(142,55%,46%,.35)}
.pc-chip--all{padding:3px 10px}
.timeline-wrap{max-height:320px;overflow-y:auto}
.tl-table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px;table-layout:fixed}
.tl-table thead{position:sticky;top:0;background:var(--surface2)}
.tl-table th{padding:4px 6px;text-align:left;color:var(--text-dim);font-size:10px;text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid var(--border)}
.tl-table td{padding:3px 6px;border-bottom:1px solid var(--border2);color:var(--text)}
.tl-table tbody tr:hover{background:var(--surface2)}
.tl-col-pc{width:90px}.tl-sortable{cursor:pointer;user-select:none}
.tl-sortable:hover{color:var(--accent)}
.tl-sorted{color:var(--accent)}
.tl-ellipsis td{color:var(--text-dim);text-align:center;letter-spacing:.1em;font-size:13px;padding:2px}
.pagination{display:flex;align-items:center;justify-content:center;gap:7px;padding:13px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);margin-top:10px}
.pagination button{background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-family:var(--mono);font-size:12px;padding:4px 9px;border-radius:3px;cursor:pointer}
.pagination button:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.pagination button:disabled{opacity:.3;cursor:not-allowed}
.page-info{font-size:12px;color:var(--text-dim)}
.pagination select{background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-size:12px;padding:4px 7px;border-radius:3px}
.empty-state{display:none;text-align:center;padding:44px;color:var(--text-dim);font-size:13px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--text-dim)}
.tl-mark-first{color:var(--cert);font-weight:600}
.tl-mark-last{color:var(--accent);font-weight:600}
.dt-ph{color:var(--text-dim);pointer-events:none}
.dt-typed{color:var(--text-hi)}
.dt-seg.filled .dt-ph{display:none}
.dt-seg.active .dt-ph,.dt-seg.active .dt-typed{color:#fff}
.finput--numkey{width:52px;text-align:center;font-family:var(--mono);-moz-appearance:textfield}
.finput--numkey::-webkit-inner-spin-button,.finput--numkey::-webkit-outer-spin-button{-webkit-appearance:none}
.numkey-wrap{position:relative;display:inline-flex;align-items:center}
.numkey-wrap .nk-arrows{display:flex;flex-direction:column;margin-left:2px;gap:1px}
.nk-arrow{width:14px;height:11px;background:var(--surface2);border:1px solid var(--border2);border-radius:2px;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:8px;color:var(--text-dim);line-height:1;transition:all .1s;user-select:none}
.nk-arrow:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-lo)}
.pc-summary-hint{font-size:10px;color:var(--text-dim);font-style:italic}
</style>"""


def _scripts() -> str:
    return r"""<script>
'use strict';
let activePCs=['all'],activeExts=['all'],activeCat='all',activePol='all',activePolArr=['all'];
let sortCol='time',sortDir='desc',currentPage=1,pageSize=1000,totalPages=1;

function numKey(e,el,min,max){
  if(e.key==='ArrowUp'){e.preventDefault();let v=parseInt(el.value,10)||min;v=Math.min(v+1,max);el.value=v;applyFilters();return;}
  if(e.key==='ArrowDown'){e.preventDefault();let v=parseInt(el.value,10)||min;v=Math.max(v-1,min);el.value=v;applyFilters();return;}
  if(e.key==='Enter'){e.preventDefault();el.blur();return;}
  const allowed=['Backspace','Delete','ArrowLeft','ArrowRight','Tab','Home','End'];
  if(allowed.includes(e.key)||(e.key>='0'&&e.key<='9')) return;
  e.preventDefault();
}
function numSanitize(el,min,max){el.value=el.value.replace(/[^0-9]/g,'');}
function numCommit(el,min,max,cb){let v=parseInt(el.value,10);if(isNaN(v)||v<min)v=min;if(v>max)v=max;el.value=v;if(cb==='applyFilters')applyFilters();}
function numStep(id,min,max,delta){const el=document.getElementById(id);if(!el)return;let v=parseInt(el.value,10)||min;v=Math.min(Math.max(v+delta,min),max);el.value=v;applyFilters();}

const SEG_LEN=[2,2,2,2,4],SEG_PH=['hh','mm','dd','mm','yyyy'],SEG_IDS=['hh','mm','dd','mo','yr'],SEG_MAX=[23,59,31,12,9999],BOUNDS=['from','to'];
const dtS={from:{vals:['','','','',''],cur:0},to:{vals:['','','','',''],cur:0}};
let _dtSegPending=false;
function dtFocus(id){document.getElementById(id).focus();}
function dtWrapClick(e,side){if(e.target.classList.contains('dt-seg'))return;const s=dtS[side];let first=-1;for(let i=0;i<5;i++)if(s.vals[i].length<SEG_LEN[i]){first=i;break;}s.cur=first===-1?4:first;dtFocus('dt-'+side);dtRender(side);}
function dtSegClick(e,side,idx){e.stopPropagation();_dtSegPending=true;dtS[side].cur=idx;dtFocus('dt-'+side);setTimeout(()=>{_dtSegPending=false;},0);dtRender(side);}
function dtActivate(side){if(_dtSegPending)return;const s=dtS[side];let first=-1;for(let i=0;i<5;i++)if(s.vals[i].length<SEG_LEN[i]){first=i;break;}s.cur=first===-1?4:first;dtRender(side);}
function dtBlur(side){SEG_IDS.forEach((_,i)=>{const el=document.getElementById(`ds-${side}-${SEG_IDS[i]}`);if(el)el.classList.remove('active');});}
function dtKey(e,side){const s=dtS[side],k=e.key;if(k>='0'&&k<='9'){e.preventDefault();const max=SEG_LEN[s.cur];if(s.vals[s.cur].length>=max)return;s.vals[s.cur]+=k;if(s.vals[s.cur].length>=max){s.vals[s.cur]=dtClamp(s.cur,s.vals[s.cur]);if(s.cur<4)s.cur++;}dtRender(side);return;}if(k==='Backspace'){e.preventDefault();if(s.vals[s.cur].length>0)s.vals[s.cur]=s.vals[s.cur].slice(0,-1);else if(s.cur>0){s.cur--;s.vals[s.cur]=s.vals[s.cur].slice(0,-1);}dtRender(side);return;}if(k==='Delete'){e.preventDefault();s.vals[s.cur]='';dtRender(side);return;}if(k==='ArrowRight'||k===':'||k==='/'){e.preventDefault();if(s.cur<4)s.cur++;dtRender(side);return;}if(k==='ArrowLeft'){e.preventDefault();if(s.cur>0)s.cur--;dtRender(side);return;}if(k==='Enter'){e.preventDefault();if(side==='from'){dtFocus('dt-to');dtActivate('to');}else{document.getElementById('dt-to').blur();applyFilters();}return;}}
function dtClamp(seg,val){const n=parseInt(val,10);if(isNaN(n))return val;return String(Math.min(n,SEG_MAX[seg])).padStart(SEG_LEN[seg],'0');}
function dtRender(side){const s=dtS[side],focused=document.getElementById('dt-'+side)===document.activeElement;for(let i=0;i<5;i++){const el=document.getElementById(`ds-${side}-${SEG_IDS[i]}`);if(!el)continue;const typed=el.querySelector('.dt-typed'),phEl=el.querySelector('.dt-ph');if(!typed||!phEl)continue;const v=s.vals[i],ph=SEG_PH[i],maxLen=SEG_LEN[i];typed.textContent=v.substring(0,maxLen);phEl.textContent=v.length<maxLen?ph.slice(v.length):'';el.classList.toggle('filled',v.length>=maxLen);el.classList.toggle('partial',v.length>0&&v.length<maxLen);el.classList.toggle('active',focused&&i===s.cur);}}
function clearDT(){BOUNDS.forEach(side=>{dtS[side].vals=['','','','',''];dtS[side].cur=0;dtRender(side);});applyFilters();}
function dtAutoFill(){const row=document.getElementById('dt-row');if(!row)return;const fromISO=row.dataset.logFrom,toISO=row.dataset.logTo;if(!fromISO||!toISO)return;function parseISO(iso,side){const m=iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);if(!m)return;dtS[side].vals=[m[4],m[5],m[3],m[2],m[1]];dtRender(side);}parseISO(fromISO,'from');parseISO(toISO,'to');}
function dtBound(side){const v=dtS[side].vals;if(v.every(s=>!s))return null;return v;}
const SIG_ORDER=[4,3,2,0,1];
function matchBound(evParts,bound,isFrom){const pairs=SIG_ORDER.map(i=>({ev:evParts[i],b:bound[i]})).filter(({b})=>b&&b.length>0);if(!pairs.length)return true;for(const{ev,b}of pairs){const evN=parseInt(ev,10),bN=parseInt(b,10);if(isFrom){if(evN>bN)return true;if(evN<bN)return false;}else{if(evN<bN)return true;if(evN>bN)return false;}}return true;}
function matchDT(isoTs,fromB,toB){if(!fromB&&!toB)return true;if(!isoTs)return false;const m=isoTs.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);if(!m)return false;const evParts=[m[4],m[5],m[3],m[2],m[1]];if(fromB&&!matchBound(evParts,fromB,true))return false;if(toB&&!matchBound(evParts,toB,false))return false;return true;}

function fmtDT(t){const d=new Date(t);return d.toLocaleDateString('en-GB',{day:'2-digit',month:'2-digit'})+' '+d.toLocaleTimeString('en-GB',{hour12:false});}
let tlSortDesc=true;
let tlPCSortAsc=true;
function tlBuildHTML(id,exp,N,sortDesc){const LIMIT=20;const show=sortDesc?exp.slice(0,Math.min(LIMIT,N)):exp.slice(Math.max(0,N-LIMIT)).reverse();const sarr=sortDesc?'▾':'▴';const psarr=tlPCSortAsc?'▾':'▴';let h=`<table class="tl-table"><thead><tr>`;h+=`<th class="tl-col-pc tl-sortable" onclick="tlTogglePC('${id}')" title="Sort by PC">PC ${psarr}</th>`;h+=`<th class="tl-col-hitdt tl-sortable tl-sorted" onclick="tlToggle('${id}')">Hit / Date · Time ${sarr}</th>`;h+=`</tr></thead><tbody>`;const _rawN=exp.length>0?Math.max(...exp.map(e=>e[2])):N;show.forEach(([t,pc,hitNum],i)=>{const isLast=(hitNum===_rawN),isFirst=(hitNum===1);const rowCls=isFirst?'tl-first':isLast?'tl-last':'';const hitMark=isFirst?`<span class="tl-mark-first">${hitNum}</span>`:isLast?`<span class="tl-mark-last">${hitNum}</span>`:hitNum;h+=`<tr class="${rowCls}"><td>${pc}</td><td>${hitMark} · ${fmtDT(t)}</td></tr>`;});if(N>LIMIT){h+=`<tr class="tl-ellipsis"><td colspan="2">· · ·</td></tr>`;if(sortDesc){const[ft,fpc,fhn]=exp[N-1];h+=`<tr class="tl-first"><td>${fpc}</td><td><span class="tl-mark-first">${fhn}</span> · ${fmtDT(ft)}</td></tr>`;}else{const[lt,lpc,lhn]=exp[0];h+=`<tr class="tl-last"><td>${lpc}</td><td><span class="tl-mark-last">${lhn}</span> · ${fmtDT(lt)}</td></tr>`;}}h+='</tbody></table>';return h;}
function tlTogglePC(id){const wrap=document.getElementById('tl-'+id);if(!wrap)return;tlPCSortAsc=!tlPCSortAsc;wrap._pcSortActive=!wrap._pcSortActive;_tlRebuild(id);}
function tlChipClick(chip,rowId){const pc=chip.dataset.pc;const wrap=document.getElementById('tl-'+rowId);if(!wrap)return;if(!wrap._tlPCs)wrap._tlPCs=new Set();if(pc==='all'){wrap._tlPCs.clear();document.querySelectorAll(`#${rowId}-d .pc-chip`).forEach(c=>c.classList.add('tl-active'));}else{const allChip=document.querySelector(`#${rowId}-d .pc-chip--all`);const isAllActive=allChip&&allChip.classList.contains('tl-active');if(isAllActive){const allPCChips=Array.from(document.querySelectorAll(`#${rowId}-d .pc-chip:not(.pc-chip--all)`));allPCChips.forEach(c=>{if(c!==chip)c.classList.add('tl-active');});chip.classList.remove('tl-active');if(allChip)allChip.classList.remove('tl-active');wrap._tlPCs.clear();allPCChips.forEach(c=>{if(c.classList.contains('tl-active'))wrap._tlPCs.add(c.dataset.pc);});}else{if(wrap._tlPCs.has(pc)){if(wrap._tlPCs.size===1)return;wrap._tlPCs.delete(pc);chip.classList.remove('tl-active');}else{wrap._tlPCs.add(pc);chip.classList.add('tl-active');const total=document.querySelectorAll(`#${rowId}-d .pc-chip:not(.pc-chip--all)`).length;if(wrap._tlPCs.size===total){wrap._tlPCs.clear();document.querySelectorAll(`#${rowId}-d .pc-chip`).forEach(c=>c.classList.add('tl-active'));}}}}  _tlRebuild(rowId);}
function _tlRebuild(rowId){const wrap=document.getElementById('tl-'+rowId);if(!wrap||!wrap._rawExp)return;if(!wrap._tlPCs)wrap._tlPCs=new Set();let exp=[...wrap._rawExp];if(wrap._tlPCs.size>0){exp=exp.filter(([t,pc])=>wrap._tlPCs.has(pc));}if(wrap._pcSortActive){exp=[...exp].sort((a,b)=>{const cmp=a[1].localeCompare(b[1],undefined,{numeric:true,sensitivity:'base'});return tlPCSortAsc?cmp:-cmp;});}const N=exp.length;wrap.innerHTML=tlBuildHTML(rowId,exp,N,tlSortDesc);wrap._exp=exp;wrap._N=N;}
function renderTimeline(id,row){const wrap=document.getElementById('tl-'+id);if(!wrap)return;const raw=row.dataset.allTimestamps;if(!raw||raw==='[]'){wrap.innerHTML='<span class="dim">No timeline data</span>';return;}try{let ts=JSON.parse(raw);if(!activePCs.includes('all'))ts=ts.filter(([t,pc])=>activePCs.includes(pc));if(!ts.length){wrap.innerHTML='<span class="dim">No hits on selected PCs</span>';return;}const exp=[];ts.forEach(([t,pc,n])=>{for(let i=0;i<n;i++)exp.push([t,pc]);});const N=exp.length;const expN=exp.map((e,i)=>[e[0],e[1],N-i]);wrap._rawExp=expN;wrap._N=N;wrap._tlPCs=new Set();wrap._pcSortActive=false;wrap.innerHTML=tlBuildHTML(id,expN,N,tlSortDesc);wrap._exp=expN;document.querySelectorAll(`#${id}-d .pc-chip`).forEach(c=>c.classList.add('tl-active'));}catch(e){wrap.innerHTML='<span class="dim">Error</span>';}}
function tlToggle(id){tlSortDesc=!tlSortDesc;const wrap=document.getElementById('tl-'+id);if(wrap&&wrap._rawExp)_tlRebuild(id);}
function toggle(id){const row=document.getElementById(id),det=document.getElementById(id+'-d'),arr=document.getElementById('arr-'+id);if(!det)return;const opening=det.classList.contains('hidden');det.classList.toggle('hidden');if(arr)arr.classList.toggle('open',opening);if(opening)renderTimeline(id,row);}
function closeAllDetails(){document.querySelectorAll('#table-body tr.detail:not(.hidden)').forEach(d=>{d.classList.add('hidden');const arr=document.getElementById('arr-'+d.id.replace(/-d$/,''));if(arr)arr.classList.remove('open');});}
function qsearch(fn){window.open('https://www.google.com/search?q='+encodeURIComponent('is "'+fn+'" a system file and is it safe'),'_blank');}
function cpHash(h){if(!h||h==='—'){alert('No hash available');return;}navigator.clipboard.writeText(h).then(()=>alert('SHA256 copied!')).catch(()=>alert('Copy failed'));}
function cpPath(p){if(!p){alert('No path available');return;}navigator.clipboard.writeText(p).then(()=>alert('Path copied!')).catch(()=>alert('Copy failed'));}
function applyFilters(){const fn=document.getElementById('fname-search').value.toLowerCase();const pth=document.getElementById('path-search').value.toLowerCase();const minH=parseInt(document.getElementById('min-hits').value)||1;const minPC=parseInt(document.getElementById('min-pcs').value)||1;const fromB=dtBound('from'),toB=dtBound('to');let visible=0;document.querySelectorAll('#table-body tr.row').forEach(r=>{const pl=(r.dataset.pcList||'').split(','),ts=r.dataset.timestamp||'';const pcCount=parseInt(r.dataset.pcCount)||0;let hits=parseInt(r.dataset.totalHits)||0;if(!activePCs.includes('all')){const ph=JSON.parse(r.dataset.pcHits||'{}');hits=activePCs.reduce((s,pc)=>s+(ph[pc]||0),0);}const ok=(activePCs.includes('all')||activePCs.some(pc=>pl.includes(pc)))&&(activeExts.includes('all')||activeExts.includes(r.dataset.ext||''))&&(activePolArr.includes('all')||activePolArr.includes(r.dataset.policy||''))&&(!fn||r.dataset.filename.includes(fn))&&(!pth||r.dataset.path.includes(pth))&&(activeCat==='all'||r.dataset.cat===activeCat)&&matchDT(ts,fromB,toB)&&hits>=minH&&pcCount>=minPC;const det=document.getElementById(r.id+'-d');if(ok){r.classList.remove('hidden');visible++;}else{r.classList.add('hidden');if(det)det.classList.add('hidden');}});document.getElementById('result-count').textContent=visible+' entries';document.getElementById('empty-state').style.display=visible===0?'block':'none';updateStats();const usePag=visible>pageSize;document.getElementById('pagination').style.display=usePag?'flex':'none';if(usePag){currentPage=1;paginateRows();}}
function _pcPillCount(){return document.querySelectorAll('#pc-pills .pill:not(:first-child)').length;}
function _syncPCPills(){const allPills=document.querySelectorAll('#pc-pills .pill');if(activePCs.includes('all')){allPills.forEach(p=>p.classList.add('active'));}else{const total=_pcPillCount();allPills.forEach(p=>{const t=p.textContent.trim();if(t==='All')p.classList.toggle('active',activePCs.length===total);else p.classList.toggle('active',activePCs.includes(t));});}}
function filterPC(pc){closeAllDetails();if(pc==='all'){activePCs=['all'];}else{if(activePCs.includes('all')){const all=Array.from(document.querySelectorAll('#pc-pills .pill:not(:first-child)')).map(p=>p.textContent.trim());activePCs=all.filter(p=>p!==pc);if(!activePCs.length){activePCs=['all'];_syncPCPills();updateHitCounts();applyFilters();return;}}else if(activePCs.includes(pc)){if(activePCs.length===1)return;activePCs=activePCs.filter(p=>p!==pc);}else{activePCs.push(pc);if(activePCs.length===_pcPillCount())activePCs=['all'];}}_syncPCPills();updateHitCounts();applyFilters();}
function _pillCount(gid){return document.querySelectorAll(`#${gid} .pill:not(:first-child)`).length;}
function _syncPills(gid,arr){const isAll=arr.includes('all'),tot=_pillCount(gid);document.querySelectorAll(`#${gid} .pill`).forEach(p=>{const t=p.textContent.trim();if(t==='All')p.classList.toggle('active',isAll||arr.length===tot);else p.classList.toggle('active',isAll||arr.includes(t));});}
function filterExt(e){activeExts=['all'];_syncPills('ext-pills',activeExts);applyFilters();}
function toggleExt(e){if(activeExts.includes('all')){const all=Array.from(document.querySelectorAll('#ext-pills .pill:not(:first-child)')).map(p=>p.textContent.trim());activeExts=all.filter(x=>x!==e);if(!activeExts.length)activeExts=['all'];}else if(activeExts.includes(e)){if(activeExts.length===1)return;activeExts=activeExts.filter(x=>x!==e);if(!activeExts.length)activeExts=['all'];}else{activeExts.push(e);if(activeExts.length===_pillCount('ext-pills'))activeExts=['all'];}_syncPills('ext-pills',activeExts);applyFilters();}
function filterPol(pol){activePolArr=['all'];activePol='all';_syncPills('pol-pills',activePolArr);applyFilters();}
function togglePol(pol){if(activePolArr.includes('all')){const all=Array.from(document.querySelectorAll('#pol-pills .pill:not(:first-child)')).map(p=>p.textContent.trim());activePolArr=all.filter(x=>x!==pol);if(!activePolArr.length)activePolArr=['all'];}else if(activePolArr.includes(pol)){if(activePolArr.length===1)return;activePolArr=activePolArr.filter(x=>x!==pol);if(!activePolArr.length)activePolArr=['all'];}else{activePolArr.push(pol);if(activePolArr.length===_pillCount('pol-pills'))activePolArr=['all'];}activePol=activePolArr.includes('all')?'all':activePolArr.join('\x00');_syncPills('pol-pills',activePolArr);applyFilters();}
function filterCat(c){activeCat=c;document.querySelectorAll('.card').forEach(x=>x.classList.remove('active'));(document.getElementById('card-'+c.replace('_',''))||document.getElementById('card-all')).classList.add('active');applyFilters();}
function filterSysBlocks(){activeCat='all';document.querySelectorAll('.card').forEach(x=>x.classList.remove('active'));document.getElementById('card-blocks').classList.add('active');document.querySelectorAll('#table-body tr.row').forEach(r=>{const e=r.dataset.eventid,det=document.getElementById(r.id+'-d');if(e==='3033'||e==='3077')r.classList.remove('hidden');else{r.classList.add('hidden');if(det)det.classList.add('hidden');}});document.getElementById('result-count').textContent=document.querySelectorAll('#table-body tr.row:not(.hidden)').length+' entries';updateStats();}
function updateHitCounts(){document.querySelectorAll('#table-body tr.row').forEach(r=>{const b=r.querySelector('.hit-pill');if(!b)return;if(activePCs.includes('all')){b.textContent=r.dataset.totalHits||'0';}else{const ph=JSON.parse(r.dataset.pcHits||'{}');b.textContent=activePCs.reduce((s,pc)=>s+(ph[pc]||0),0);}});}
function updateStats(){const vis=document.querySelectorAll('#table-body tr.row:not(.hidden)');let s={tot:0,cert:0,hash:0,nc:0,blk:0};vis.forEach(r=>{s.tot++;const c=r.dataset.cat,e=r.dataset.eventid;if(c==='publisher_signed')s.cert++;else if(c==='hash_only')s.hash++;else if(c==='unknown')s.nc++;if(e==='3033'||e==='3077')s.blk++;});document.querySelector('#card-all .card-num').textContent=s.tot;document.querySelector('#card-publishersigned .card-num').textContent=s.cert;document.querySelector('#card-hashonly .card-num').textContent=s.hash;document.querySelector('#card-unknown .card-num').textContent=s.nc;document.querySelector('#card-blocks .card-num').textContent=s.blk;}
function sortTable(c){if(sortCol===c)sortDir=sortDir==='asc'?'desc':'asc';else{sortCol=c;sortDir='desc';}const tb=document.getElementById('table-body'),rows=Array.from(tb.querySelectorAll('tr.row'));rows.sort((a,b)=>{let av,bv;switch(c){case'type':av=a.dataset.cat||'';bv=b.dataset.cat||'';break;case'time':av=a.dataset.timestamp||'';bv=b.dataset.timestamp||'';break;case'file':av=a.dataset.filename||'';bv=b.dataset.filename||'';break;case'publisher':av=a.querySelector('.col-pub').textContent.trim();bv=b.querySelector('.col-pub').textContent.trim();break;case'hits':av=parseInt(a.dataset.totalHits)||0;bv=parseInt(b.dataset.totalHits)||0;break;default:return 0;}const d=sortDir==='asc'?1:-1;return av<bv?-d:(av>bv?d:0);});rows.forEach(r=>{tb.appendChild(r);const d=document.getElementById(r.id+'-d');if(d)tb.appendChild(d);});document.querySelectorAll('thead th').forEach(t=>{t.classList.remove('sorted');const a=t.querySelector('.sarr');if(a)a.textContent='';});const th=document.querySelector(`thead th[onclick*="${sortCol}"]`);if(th){th.classList.add('sorted');const a=th.querySelector('.sarr');if(a)a.textContent=sortDir==='asc'?'▴':'▾';}}
function clearCat(){activeCat='all';document.querySelectorAll('.card').forEach(x=>x.classList.remove('active'));document.getElementById('card-all').classList.add('active');applyFilters();}
function resetFilters(){document.getElementById('fname-search').value='';document.getElementById('path-search').value='';document.getElementById('min-hits').value='1';document.getElementById('min-pcs').value='1';activeExts=['all'];activeCat='all';activePol='all';activePolArr=['all'];dtAutoFill();document.querySelectorAll('.card').forEach(x=>x.classList.remove('active'));document.getElementById('card-all').classList.add('active');activePCs=['all'];_syncPCPills();_syncPills('ext-pills',activeExts);_syncPills('pol-pills',activePolArr);updateHitCounts();applyFilters();}
function paginateRows(){const vr=Array.from(document.querySelectorAll('#table-body tr.row:not(.hidden)'));totalPages=Math.max(1,Math.ceil(vr.length/pageSize));currentPage=Math.min(currentPage,totalPages);const s=(currentPage-1)*pageSize,e=s+pageSize;vr.forEach((r,i)=>{const det=document.getElementById(r.id+'-d');const show=i>=s&&i<e;r.style.display=show?'':'none';if(det)det.style.display=show?'':'none';});document.getElementById('current-page').textContent=currentPage;document.getElementById('total-pages').textContent=totalPages;['btn-first','btn-prev'].forEach(id=>document.getElementById(id).disabled=currentPage===1);['btn-next','btn-last'].forEach(id=>document.getElementById(id).disabled=currentPage===totalPages);}
function goToPage(p){currentPage=Math.max(1,Math.min(p,totalPages));paginateRows();}
function changePageSize(sel){pageSize=parseInt(sel.value);currentPage=1;paginateRows();}
function toggleColl(btn){btn.classList.toggle('open');const detail=btn.nextElementSibling;if(detail)detail.classList.toggle('hidden');}
document.addEventListener('DOMContentLoaded',()=>{BOUNDS.forEach(side=>dtRender(side));dtAutoFill();sortTable('time');updateStats();updateHitCounts();_syncPCPills();_syncPills('ext-pills',activeExts);_syncPills('pol-pills',activePolArr);});
</script>"""
, pc)
        if m:
            prefix, num = m.group(1), int(m.group(2))
            groups.setdefault(prefix, []).append(num)
        else:
            no_num.append(pc)

    parts: list[str] = []
    for prefix in sorted(groups.keys()):
        nums = sorted(set(groups[prefix]))   # deduplicate same numbers under one prefix
        range_start = range_end = nums[0]
        for n in nums[1:]:
            if n == range_end + 1:
                range_end = n
            else:
                parts.append(f"{prefix}{range_start}" if range_start == range_end
                             else f"{prefix}{range_start}–{range_end}")
                range_start = range_end = n
        parts.append(f"{prefix}{range_start}" if range_start == range_end
                     else f"{prefix}{range_start}–{range_end}")

    return ", ".join(parts + sorted(no_num))


def _fmt(dt: datetime | None) -> tuple[str, str, str]:
    if dt:
        return dt.strftime("%d/%m %H:%M"), dt.isoformat(), dt.strftime("%d/%m/%Y %H:%M:%S")
    return "—", "", "—"


def _gen_row(e: LogEntry, idx: int) -> str:
    cat    = e.category
    badge  = _BADGES.get(cat, _BADGES["unknown"])
    fpath  = e.filepath
    fname  = e.filename or Path(fpath).name or fpath
    pub    = e.publisher or "—"
    sha256 = e.sha256 or "—"
    proc   = e.processname or "—"
    eid    = e.eventid
    ptype  = e.policy_type
    pname  = e.policyname or "—"
    pguid  = e.policyguid or "—"
    orig   = e.originalfilename or "—"
    pc_cnt = len(e.pcs)
    total  = e.total_hits

    elabel, eclass = _EVENT_LABELS.get(eid, ("Unknown", "unknown"))
    disp, iso, _   = _fmt(e.last_seen or e.dt)

    pc_list   = ",".join(sorted(e.pcs, key=natural_sort_key))
    pc_hits_j = json.dumps(e.pc_hits).replace('"', '&quot;')
    sorted_ts = sorted(e.all_timestamps, key=lambda x: x[0], reverse=True)
    ts_j      = json.dumps([[t.isoformat(), pc, hits] for t, pc, hits in sorted_ts]).replace('"', '&quot;')

    row_cls = "row"
    if cat == "unknown": row_cls += " row--nocert"
    if eid in ("3033", "3077"): row_cls += " row--block"

    pbadge = f'<span class="policy-badge policy-{ptype}">{ptype}</span>'
    row_id_for_chips = f"r{idx}"
    chips  = "".join(
        f'<span class="pc-chip" data-pc="{sanitize_xml(pc)}" onclick="tlChipClick(this,\'{row_id_for_chips}\')" title="Filter timeline to this PC">'
        f'<span class="pc-chip__name">{sanitize_xml(pc)}</span>'
        f'<span class="pc-chip__hits">{hits}</span></span>'
        for pc, hits in sorted(e.pc_hits.items(), key=lambda x: natural_sort_key(x[0]))
    )
    all_chip = (
        f'<span class="pc-chip pc-chip--all tl-active" data-pc="all" '
        f'onclick="tlChipClick(this,\'{row_id_for_chips}\')" title="Show all PCs">'
        f'<span class="pc-chip__name">All</span></span>'
    )
    pc_summary = (
        f'<div class="pc-summary">Found on <strong>{pc_cnt}</strong> PC'
        f'{"s" if pc_cnt != 1 else ""} · <strong>{total}</strong> hits</div>'
        f'<div class="pc-chips">{all_chip}{chips}</div>'
    )

    row_id = f"r{idx}"
    fn_esc = sanitize_xml(fname).replace("'", "\\'")

    main = f"""\
    <tr class="{row_cls}" id="{row_id}"
      data-pc-list="{sanitize_xml(pc_list)}"
      data-pc-hits="{pc_hits_j}"
      data-all-timestamps="{ts_j}"
      data-total-hits="{total}"
      data-pc-count="{pc_cnt}"
      data-ext="{sanitize_xml(e.extension)}"
      data-timestamp="{iso}"
      data-filename="{sanitize_xml(fname.lower())}"
      data-path="{sanitize_xml(fpath.lower())}"
      data-cat="{cat}"
      data-policy="{sanitize_xml(pname)}"
      data-eventid="{eid}"
      onclick="toggle('{row_id}')" style="cursor:pointer">
      <td class="col-badge">{badge}</td>
      <td class="col-time mono">{disp}</td>
      <td class="col-file">
        <span class="fname">{sanitize_xml(fname)}</span>
        <span class="fpath">{sanitize_xml(fpath)}</span>
      </td>
      <td class="col-pub">{sanitize_xml(pub) if pub != "—" else '<span class="dim">—</span>'}</td>
      <td class="col-hits"><span class="hit-pill">{total}</span></td>
      <td class="col-exp"><span class="exp-arrow" id="arr-{row_id}">▾</span></td>
    </tr>"""

    detail = f"""\
    <tr class="detail hidden" id="{row_id}-d">
      <td colspan="6">
        <div class="detail-panel">
          <div class="dp-actions">
            <span class="ev-badge ev-{eclass} dp-event-badge">{eid} — {elabel}</span>
            <button class="dp-btn" onclick="qsearch('{fn_esc}')">🔍 Is &quot;{sanitize_xml(fname)}&quot; a system file?</button>
            <button class="dp-btn" onclick="cpHash('{sanitize_xml(sha256)}')">📋 Copy SHA256</button>
            <button class="dp-btn" data-fp="{sanitize_xml(fpath)}" onclick="cpPath(this.dataset.fp)">📁 Copy path</button>
          </div>
          <div class="dp-grid">
            <div class="dp-section">
              <div class="dp-title">File</div>
              <dl class="dp-dl">
                <dt>Full path</dt><dd><code class="dp-hi">{sanitize_xml(fpath)}</code></dd>
                <dt>Called by</dt><dd><code class="dp-hi">{sanitize_xml(proc)}</code></dd>
                <dt>Original name</dt><dd><span class="dp-hi">{sanitize_xml(orig)}</span></dd>
              </dl>
            </div>
            <div class="dp-section">
              <div class="dp-title">Policy &amp; signature</div>
              <dl class="dp-dl">
                <dt>Policy</dt><dd><span class="dp-hi">{sanitize_xml(pname)}</span> {pbadge}</dd>
                <dt>Publisher</dt><dd><span class="dp-hi">{sanitize_xml(pub)}</span></dd>
                <dt>SHA256</dt><dd><code class="mono hash-code dp-hi">{sanitize_xml(sha256)}</code></dd>
                <dt>GUID</dt><dd><code class="mono no-box dp-hi">{sanitize_xml(pguid)}</code></dd>
              </dl>
            </div>
          </div>
          <div class="dp-section">
            <div class="dp-title">PC distribution</div>
            {pc_summary}
          </div>
          <div class="dp-section">
            <div class="dp-title">Activity timeline <span class="pc-summary-hint">· click PC chips above to filter</span></div>
            <div id="tl-{row_id}" class="timeline-wrap">Loading…</div>
          </div>
        </div>
      </td>
    </tr>"""

    return main + "\n" + detail


def _css() -> str:
    return """<style>
:root{
  --bg:        hsl(0,0%,9%);
  --surface:   hsl(0,0%,12%);
  --surface2:  hsl(0,0%,14%);
  --border:    hsl(0,0%,22%);
  --border2:   hsl(0,0%,18%);
  --text:      hsl(0,0%,80%);
  --text-dim:  hsl(0,0%,45%);
  --text-hi:   hsl(0,0%,94%);
  --accent:    hsl(208,100%,42%);
  --accent-lo: hsla(208,100%,42%,0.14);
  --accent-brd:hsla(208,100%,42%,0.35);
  --cert:      hsl(142,55%,46%);
  --hash:      hsl(38,78%,50%);
  --nocert:    hsl(0,65%,56%);
  --block:     hsl(28,88%,50%);
  --hl-bg:     hsla(50,85%,50%,0.13);
  --hl-brd:    hsl(48,82%,50%);
  --mono:      'JetBrains Mono',monospace;
  --sans:      'IBM Plex Sans',sans-serif;
  --r:         6px;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.5;min-height:100vh;user-select:none;-webkit-user-select:none}
code,.mono{font-family:var(--mono)}
input,textarea,code,pre,.dp-dl dd,.selectable{user-select:text;-webkit-user-select:text}
.shell{max-width:1700px;margin:0 auto;padding:18px 22px}
.site-header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:14px;border-bottom:1px solid var(--border);margin-bottom:18px}
.header-left{display:flex;align-items:center}
.logo-block{display:flex;align-items:center;gap:12px}
.logo-svg{flex-shrink:0;filter:drop-shadow(0 0 6px hsla(208,100%,42%,.25))}
h1{font-size:18px;font-weight:600;color:var(--text-hi);letter-spacing:-.2px}
h1 .accent{color:var(--accent)}
.coll-wrap{display:flex;flex-direction:column;align-items:flex-end;gap:4px;position:relative}
.coll-summary{display:flex;align-items:center;gap:9px;background:var(--surface2);border:1px solid var(--border2);border-radius:var(--r);padding:5px 12px;font-size:11px;white-space:nowrap;cursor:pointer;transition:border-color .1s;color:var(--text);font-family:var(--sans)}
.coll-summary:hover{border-color:var(--accent)}
.coll-meta{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim)}
.coll-meta-val{font-family:var(--mono);color:var(--accent);text-transform:none;letter-spacing:0}
.coll-range{font-family:var(--mono);color:var(--accent)}
.coll-pipe{color:var(--border);font-size:12px;flex-shrink:0}
.coll-chevron{color:var(--text-dim);font-size:10px;transition:transform .15s;display:inline-block;margin-left:2px}
.coll-summary.open .coll-chevron{transform:rotate(180deg)}
.coll-detail{position:absolute;top:calc(100% + 5px);right:0;display:flex;flex-wrap:wrap;justify-content:flex-start;gap:5px;background:var(--surface);border:1px solid var(--border2);border-radius:var(--r);padding:8px 9px;min-width:100%;box-sizing:border-box;box-shadow:0 4px 14px hsla(0,0%,0%,.35);z-index:20}
.coll-detail.hidden{display:none}
.coll-run{display:flex;align-items:center;gap:6px;background:var(--surface2);border:1px solid var(--border2);border-radius:var(--r);padding:3px 9px;font-size:11px;white-space:nowrap;flex:1 0 200px;max-width:calc(33.333% - 4px);box-sizing:border-box}
.coll-ts{font-family:var(--mono);color:var(--accent);flex-shrink:0}
.coll-sep{color:var(--text-dim);flex-shrink:0;padding:0 2px}
.coll-pcs{color:var(--text-dim);flex-shrink:0}
.warn-bar{display:flex;align-items:flex-start;gap:10px;background:hsla(38,80%,40%,.08);border:1px solid hsla(38,80%,40%,.28);border-radius:var(--r);padding:9px 13px;margin-bottom:14px}
.warn-icon{color:var(--block);font-size:14px;flex-shrink:0;margin-top:1px}
.warn-bar ul{list-style:none;display:flex;flex-direction:column;gap:2px}
.warn-bar li{font-size:12px;color:var(--hash)}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:12px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:12px 14px 9px;cursor:pointer;transition:border-color .12s,background .12s;position:relative;overflow:hidden}
.card:hover{background:var(--surface2);border-color:var(--accent)}
.card.active{background:var(--surface2)}
.card--total.active{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent-brd) inset}
.card--cert.active {border-color:var(--cert);box-shadow:0 0 0 1px hsla(142,55%,46%,.35) inset}
.card--future.active{border-color:var(--border);cursor:default}
.card--nocert.active{border-color:var(--nocert);box-shadow:0 0 0 1px hsla(0,65%,56%,.35) inset}
.card--block.active {border-color:hsl(0,0%,55%);box-shadow:0 0 0 1px hsla(0,0%,55%,.4) inset}
.card--cert:hover {border-color:var(--cert)}
.card--nocert:hover{border-color:var(--nocert)}
.card--block:hover {border-color:hsl(0,0%,55%)}
.card--future{opacity:.45;cursor:default}
.card--future:hover{background:var(--surface);border-color:var(--border)}
.card-num--dim{color:var(--text-dim)}
.card-num{font-family:var(--mono);font-size:24px;font-weight:600;color:var(--text-hi);line-height:1;margin-bottom:4px}
.card-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-dim)}
.card-bar{position:absolute;bottom:0;left:0;height:2px;transition:width .4s ease}
.card--total .card-bar{background:var(--text-dim)}
.card--total.active .card-bar,.card--total:hover .card-bar{background:var(--accent)}
.card--cert  .card-bar{background:var(--cert)}
.card--future .card-bar{background:transparent}
.card--nocert .card-bar{background:var(--nocert)}
.card--block .card-bar{background:hsl(0,0%,55%)}
.filter-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:11px 13px;margin-bottom:10px;display:flex;flex-direction:column;gap:9px}
.frow{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.frow--wrap{flex-wrap:wrap}
.frow-label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-dim);min-width:42px;flex-shrink:0}
.fdivider{border-top:1px solid var(--border2);margin:1px 0}
.pills{display:flex;flex-wrap:wrap;gap:4px}
.pill{background:transparent;border:1px solid var(--border);color:var(--text-dim);font-size:11px;font-family:var(--mono);padding:3px 9px;border-radius:5px;cursor:pointer;transition:all .1s}
.pill:hover{border-color:var(--accent);color:var(--accent)}
.pill.active{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600;letter-spacing:.3px}
.finput-group{display:flex;flex-direction:column;gap:3px}
.finput-group--sm{min-width:0}
.finput-label{font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}
.finput{background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-family:var(--sans);font-size:12px;padding:5px 9px;border-radius:5px;outline:none;transition:border-color .1s;width:100%}
.finput:focus{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-lo)}
.fbtn{background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-size:11px;font-family:var(--sans);padding:5px 11px;border-radius:5px;cursor:pointer;transition:all .1s;white-space:nowrap;text-transform:uppercase;letter-spacing:.4px;height:28px;display:flex;align-items:center}
.fbtn:hover{border-color:var(--accent);color:var(--accent)}
.fbtn--reset:hover{border-color:var(--nocert);color:var(--nocert)}
.fbtn--clr{padding:4px 8px;color:var(--text-dim);border-color:transparent;background:transparent;font-size:13px;height:auto;align-self:center}
.fbtn--clr:hover{color:var(--nocert);border-color:var(--nocert)}
.frow--dt{align-items:flex-start}
.dt-block{display:flex;flex-direction:column;gap:4px}
.dt-row{display:flex;align-items:center;gap:8px}
.dt-mask-wrap{position:relative;display:inline-flex;align-items:center;background:var(--surface2);border:1px solid var(--border2);border-radius:5px;padding:5px 10px;cursor:text;font-family:var(--mono);font-size:12px;transition:border-color .1s;user-select:none;white-space:nowrap}
.dt-mask-wrap:focus-within{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-lo)}
.dt-seg{display:inline-block;padding:0 1px;border-radius:2px;color:var(--text-dim);transition:color .1s,background .1s;cursor:pointer}
.dt-seg.filled{color:var(--text-hi)}
.dt-seg.active{background:var(--accent);color:#fff;border-radius:2px}
.dt-sep{color:var(--border);padding:0 1px;pointer-events:none;user-select:none}
.dt-spc{padding:0 3px;pointer-events:none}
.dt-hidden{position:absolute;opacity:0;pointer-events:none;width:1px;height:1px;top:0;left:0;border:none;background:transparent;outline:none;font-size:1px}
.dt-arrow{color:var(--text-dim);font-size:13px;flex-shrink:0}
.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.table-toolbar{display:flex;justify-content:space-between;align-items:center;padding:9px 14px;border-bottom:1px solid var(--border)}
.toolbar-title{font-weight:600;font-size:11px;color:var(--text-hi);text-transform:uppercase;letter-spacing:.5px}
.entry-count{font-family:var(--mono);font-size:11px;font-weight:600;background:var(--accent-lo);color:var(--accent);border:1px solid var(--accent-brd);padding:2px 9px;border-radius:3px}
.main-table{width:100%;border-collapse:collapse}
thead th{background:var(--surface2);padding:7px 11px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-dim);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover,thead th.sorted{color:var(--accent)}
.sarr{font-size:11px;margin-left:4px;opacity:.6}
thead th.sorted .sarr{opacity:1;color:var(--accent)}
.col-badge{width:88px}.col-time{width:98px}.col-file{min-width:260px}
.col-pub{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.col-hits{width:58px;text-align:center}.col-exp{width:34px;text-align:center}
tbody tr.row{border-bottom:1px solid var(--border2);transition:background .08s}
tbody tr.row:hover{background:var(--surface2)}
tbody tr.row td:first-child{position:relative;padding-left:14px}
tbody tr.row td:first-child::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:transparent;transition:background .08s}
tbody tr.row--nocert td:first-child::before{background:var(--nocert)}
tbody tr.row--multi td:first-child::before{background:var(--hl-brd)}
tbody tr.row--block td:first-child::before{background:hsl(0,0%,55%)}
tbody tr.row--block.row--nocert td:first-child::before{background:hsl(0,0%,55%)}
tbody tr.row--multi{background:var(--hl-bg)!important}
tbody tr.row--multi:hover{background:hsla(50,85%,50%,0.11)!important}
tbody tr.row.hidden{display:none}
tbody tr.detail{background:var(--bg);border-bottom:1px solid var(--border);border-top:1px solid var(--border2)}
tbody tr.detail.hidden{display:none}
td{padding:8px 11px;vertical-align:middle;font-size:12px}
.fname{display:block;color:var(--text-hi);font-family:var(--mono);font-size:12px;font-weight:600}
.fpath{display:block;color:var(--text-dim);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:440px}
.hit-pill{background:var(--accent-lo);color:var(--accent);font-family:var(--mono);font-size:11px;font-weight:600;padding:2px 7px;border-radius:3px;border:1px solid var(--accent-brd)}
.exp-arrow{color:var(--text-dim);font-size:12px;display:inline-block;transition:transform .13s}
.exp-arrow.open{transform:rotate(180deg)}
.dim{color:var(--text-dim)}
.badge{display:inline-block;padding:2px 6px;border-radius:5px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;font-family:var(--mono)}
.badge.ms  {background:hsla(0,0%,50%,.12);color:var(--text-dim);border:1px solid hsla(0,0%,50%,.25)}
.badge.pub {background:hsla(142,55%,46%,.12);color:var(--cert);border:1px solid hsla(142,55%,46%,.3)}
.badge.sys {background:hsla(0,0%,50%,.10);color:var(--text-dim);border:1px solid hsla(0,0%,50%,.2)}
.badge.hash{background:hsla(38,78%,50%,.12);color:var(--hash);border:1px solid hsla(38,78%,50%,.3)}
.badge.unk {background:hsla(0,65%,56%,.12);color:var(--nocert);border:1px solid hsla(0,65%,56%,.3)}
.ev-badge{display:inline-block;padding:2px 7px;border-radius:3px;font-size:11px;font-family:var(--mono)}
.ev-audit  {background:hsla(38,78%,50%,.12);color:var(--hash);border:1px solid hsla(38,78%,50%,.25)}
.ev-enforce{background:hsla(0,65%,56%,.12);color:var(--nocert);border:1px solid hsla(0,65%,56%,.25)}
.ev-unknown{background:hsla(0,0%,50%,.10);color:var(--text-dim);border:1px solid hsla(0,0%,50%,.2)}
.policy-badge{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-family:var(--sans);font-weight:500;margin-left:5px;vertical-align:middle}
.policy-windows{background:hsla(0,0%,50%,.12);color:var(--text-dim);border:1px solid hsla(0,0%,50%,.22)}
.policy-custom {background:var(--accent-lo);color:var(--accent);border:1px solid var(--accent-brd)}
.policy-unknown{background:hsla(38,78%,50%,.12);color:var(--hash);border:1px solid hsla(38,78%,50%,.3)}
.detail-panel{padding:16px 16px 14px;display:flex;flex-direction:column;gap:14px;background:var(--bg)}
.dp-actions{display:flex;gap:7px;flex-wrap:wrap}
.dp-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);font-size:11px;font-family:var(--sans);padding:5px 11px;border-radius:5px;cursor:pointer;transition:all .12s;display:flex;align-items:center;gap:5px;letter-spacing:.1px}
.dp-btn:hover{border-color:var(--accent);color:var(--accent)}
.dp-grid{display:flex;flex-direction:column;gap:12px}
.dp-section{background:var(--surface);border:1px solid var(--border2);border-radius:6px;padding:10px 12px}
.dp-title{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--accent);margin-bottom:8px;font-weight:600}
.dp-dl{display:grid;grid-template-columns:90px 1fr;gap:4px 12px;font-size:12px}
.dp-dl dt{color:var(--text-dim);font-size:10px;text-transform:uppercase;letter-spacing:.5px;align-self:start;padding-top:2px}
.dp-dl dd{color:var(--text);word-break:break-all;min-width:0}
.dp-dl code{background:var(--surface2);color:var(--text);padding:2px 5px;border-radius:2px;word-break:break-all;white-space:pre-wrap;overflow-wrap:anywhere;display:block}
.dp-dl code.no-box{background:transparent;padding:0;border-radius:0;font-family:var(--mono);font-size:11px}
.dp-dl code.no-box.dp-hi{background:hsla(0,0%,94%,.07);padding:1px 4px;border-radius:3px}
.hash-code{font-size:10px;letter-spacing:.4px}
.dp-hi{color:var(--text-hi);background:hsla(0,0%,94%,.07);border-radius:3px;padding:1px 4px;display:inline-block}
code.dp-hi{background:hsla(0,0%,94%,.07);padding:2px 5px;border-radius:2px;display:inline;white-space:normal}
.dp-event-badge{display:inline-flex;align-items:center;padding:5px 10px;font-size:11px;border-radius:5px;font-family:var(--mono);flex-shrink:0}
.pc-summary{font-size:12px;color:var(--text);margin-bottom:6px}
.pc-summary strong{color:var(--text-hi)}
.pc-chips{display:flex;flex-wrap:wrap;gap:5px}
.pc-chip{display:inline-flex;align-items:center;gap:5px;background:var(--surface2);border:1px solid var(--border2);border-radius:5px;padding:3px 8px;cursor:pointer;transition:border-color .1s,box-shadow .1s}
.pc-chip:hover{border-color:var(--accent)}
.pc-chip.tl-active{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.pc-chip__name{font-family:var(--mono);font-size:11px;color:var(--text)}
.pc-chip__hits{background:var(--surface);color:var(--text-dim);border:1px solid var(--border);font-family:var(--mono);font-size:10px;font-weight:600;padding:1px 5px;border-radius:4px;transition:background .1s,color .1s,border-color .1s}
.pc-chip.tl-active .pc-chip__hits{background:hsla(142,55%,46%,.12);color:var(--cert);border-color:hsla(142,55%,46%,.35)}
.pc-chip--all{padding:3px 10px}
.timeline-wrap{max-height:320px;overflow-y:auto}
.tl-table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px;table-layout:fixed}
.tl-table thead{position:sticky;top:0;background:var(--surface2)}
.tl-table th{padding:4px 6px;text-align:left;color:var(--text-dim);font-size:10px;text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid var(--border)}
.tl-table td{padding:3px 6px;border-bottom:1px solid var(--border2);color:var(--text)}
.tl-table tbody tr:hover{background:var(--surface2)}
.tl-col-pc{width:90px}.tl-sortable{cursor:pointer;user-select:none}
.tl-sortable:hover{color:var(--accent)}
.tl-sorted{color:var(--accent)}
.tl-ellipsis td{color:var(--text-dim);text-align:center;letter-spacing:.1em;font-size:13px;padding:2px}
.pagination{display:flex;align-items:center;justify-content:center;gap:7px;padding:13px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);margin-top:10px}
.pagination button{background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-family:var(--mono);font-size:12px;padding:4px 9px;border-radius:3px;cursor:pointer}
.pagination button:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.pagination button:disabled{opacity:.3;cursor:not-allowed}
.page-info{font-size:12px;color:var(--text-dim)}
.pagination select{background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-size:12px;padding:4px 7px;border-radius:3px}
.empty-state{display:none;text-align:center;padding:44px;color:var(--text-dim);font-size:13px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--text-dim)}
.tl-mark-first{color:var(--cert);font-weight:600}
.tl-mark-last{color:var(--accent);font-weight:600}
.dt-ph{color:var(--text-dim);pointer-events:none}
.dt-typed{color:var(--text-hi)}
.dt-seg.filled .dt-ph{display:none}
.dt-seg.active .dt-ph,.dt-seg.active .dt-typed{color:#fff}
.finput--numkey{width:52px;text-align:center;font-family:var(--mono);-moz-appearance:textfield}
.finput--numkey::-webkit-inner-spin-button,.finput--numkey::-webkit-outer-spin-button{-webkit-appearance:none}
.numkey-wrap{position:relative;display:inline-flex;align-items:center}
.numkey-wrap .nk-arrows{display:flex;flex-direction:column;margin-left:2px;gap:1px}
.nk-arrow{width:14px;height:11px;background:var(--surface2);border:1px solid var(--border2);border-radius:2px;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:8px;color:var(--text-dim);line-height:1;transition:all .1s;user-select:none}
.nk-arrow:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-lo)}
.pc-summary-hint{font-size:10px;color:var(--text-dim);font-style:italic}
</style>"""


def _scripts() -> str:
    return r"""<script>
'use strict';
let activePCs=['all'],activeExts=['all'],activeCat='all',activePol='all',activePolArr=['all'];
let sortCol='time',sortDir='desc',currentPage=1,pageSize=1000,totalPages=1;

function numKey(e,el,min,max){
  if(e.key==='ArrowUp'){e.preventDefault();let v=parseInt(el.value,10)||min;v=Math.min(v+1,max);el.value=v;applyFilters();return;}
  if(e.key==='ArrowDown'){e.preventDefault();let v=parseInt(el.value,10)||min;v=Math.max(v-1,min);el.value=v;applyFilters();return;}
  if(e.key==='Enter'){e.preventDefault();el.blur();return;}
  const allowed=['Backspace','Delete','ArrowLeft','ArrowRight','Tab','Home','End'];
  if(allowed.includes(e.key)||(e.key>='0'&&e.key<='9')) return;
  e.preventDefault();
}
function numSanitize(el,min,max){el.value=el.value.replace(/[^0-9]/g,'');}
function numCommit(el,min,max,cb){let v=parseInt(el.value,10);if(isNaN(v)||v<min)v=min;if(v>max)v=max;el.value=v;if(cb==='applyFilters')applyFilters();}
function numStep(id,min,max,delta){const el=document.getElementById(id);if(!el)return;let v=parseInt(el.value,10)||min;v=Math.min(Math.max(v+delta,min),max);el.value=v;applyFilters();}

const SEG_LEN=[2,2,2,2,4],SEG_PH=['hh','mm','dd','mm','yyyy'],SEG_IDS=['hh','mm','dd','mo','yr'],SEG_MAX=[23,59,31,12,9999],BOUNDS=['from','to'];
const dtS={from:{vals:['','','','',''],cur:0},to:{vals:['','','','',''],cur:0}};
let _dtSegPending=false;
function dtFocus(id){document.getElementById(id).focus();}
function dtWrapClick(e,side){if(e.target.classList.contains('dt-seg'))return;const s=dtS[side];let first=-1;for(let i=0;i<5;i++)if(s.vals[i].length<SEG_LEN[i]){first=i;break;}s.cur=first===-1?4:first;dtFocus('dt-'+side);dtRender(side);}
function dtSegClick(e,side,idx){e.stopPropagation();_dtSegPending=true;dtS[side].cur=idx;dtFocus('dt-'+side);setTimeout(()=>{_dtSegPending=false;},0);dtRender(side);}
function dtActivate(side){if(_dtSegPending)return;const s=dtS[side];let first=-1;for(let i=0;i<5;i++)if(s.vals[i].length<SEG_LEN[i]){first=i;break;}s.cur=first===-1?4:first;dtRender(side);}
function dtBlur(side){SEG_IDS.forEach((_,i)=>{const el=document.getElementById(`ds-${side}-${SEG_IDS[i]}`);if(el)el.classList.remove('active');});}
function dtKey(e,side){const s=dtS[side],k=e.key;if(k>='0'&&k<='9'){e.preventDefault();const max=SEG_LEN[s.cur];if(s.vals[s.cur].length>=max)return;s.vals[s.cur]+=k;if(s.vals[s.cur].length>=max){s.vals[s.cur]=dtClamp(s.cur,s.vals[s.cur]);if(s.cur<4)s.cur++;}dtRender(side);return;}if(k==='Backspace'){e.preventDefault();if(s.vals[s.cur].length>0)s.vals[s.cur]=s.vals[s.cur].slice(0,-1);else if(s.cur>0){s.cur--;s.vals[s.cur]=s.vals[s.cur].slice(0,-1);}dtRender(side);return;}if(k==='Delete'){e.preventDefault();s.vals[s.cur]='';dtRender(side);return;}if(k==='ArrowRight'||k===':'||k==='/'){e.preventDefault();if(s.cur<4)s.cur++;dtRender(side);return;}if(k==='ArrowLeft'){e.preventDefault();if(s.cur>0)s.cur--;dtRender(side);return;}if(k==='Enter'){e.preventDefault();if(side==='from'){dtFocus('dt-to');dtActivate('to');}else{document.getElementById('dt-to').blur();applyFilters();}return;}}
function dtClamp(seg,val){const n=parseInt(val,10);if(isNaN(n))return val;return String(Math.min(n,SEG_MAX[seg])).padStart(SEG_LEN[seg],'0');}
function dtRender(side){const s=dtS[side],focused=document.getElementById('dt-'+side)===document.activeElement;for(let i=0;i<5;i++){const el=document.getElementById(`ds-${side}-${SEG_IDS[i]}`);if(!el)continue;const typed=el.querySelector('.dt-typed'),phEl=el.querySelector('.dt-ph');if(!typed||!phEl)continue;const v=s.vals[i],ph=SEG_PH[i],maxLen=SEG_LEN[i];typed.textContent=v.substring(0,maxLen);phEl.textContent=v.length<maxLen?ph.slice(v.length):'';el.classList.toggle('filled',v.length>=maxLen);el.classList.toggle('partial',v.length>0&&v.length<maxLen);el.classList.toggle('active',focused&&i===s.cur);}}
function clearDT(){BOUNDS.forEach(side=>{dtS[side].vals=['','','','',''];dtS[side].cur=0;dtRender(side);});applyFilters();}
function dtAutoFill(){const row=document.getElementById('dt-row');if(!row)return;const fromISO=row.dataset.logFrom,toISO=row.dataset.logTo;if(!fromISO||!toISO)return;function parseISO(iso,side){const m=iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);if(!m)return;dtS[side].vals=[m[4],m[5],m[3],m[2],m[1]];dtRender(side);}parseISO(fromISO,'from');parseISO(toISO,'to');}
function dtBound(side){const v=dtS[side].vals;if(v.every(s=>!s))return null;return v;}
const SIG_ORDER=[4,3,2,0,1];
function matchBound(evParts,bound,isFrom){const pairs=SIG_ORDER.map(i=>({ev:evParts[i],b:bound[i]})).filter(({b})=>b&&b.length>0);if(!pairs.length)return true;for(const{ev,b}of pairs){const evN=parseInt(ev,10),bN=parseInt(b,10);if(isFrom){if(evN>bN)return true;if(evN<bN)return false;}else{if(evN<bN)return true;if(evN>bN)return false;}}return true;}
function matchDT(isoTs,fromB,toB){if(!fromB&&!toB)return true;if(!isoTs)return false;const m=isoTs.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);if(!m)return false;const evParts=[m[4],m[5],m[3],m[2],m[1]];if(fromB&&!matchBound(evParts,fromB,true))return false;if(toB&&!matchBound(evParts,toB,false))return false;return true;}

function fmtDT(t){const d=new Date(t);return d.toLocaleDateString('en-GB',{day:'2-digit',month:'2-digit'})+' '+d.toLocaleTimeString('en-GB',{hour12:false});}
let tlSortDesc=true;
let tlPCSortAsc=true;
function tlBuildHTML(id,exp,N,sortDesc){const LIMIT=20;const show=sortDesc?exp.slice(0,Math.min(LIMIT,N)):exp.slice(Math.max(0,N-LIMIT)).reverse();const sarr=sortDesc?'▾':'▴';const psarr=tlPCSortAsc?'▾':'▴';let h=`<table class="tl-table"><thead><tr>`;h+=`<th class="tl-col-pc tl-sortable" onclick="tlTogglePC('${id}')" title="Sort by PC">PC ${psarr}</th>`;h+=`<th class="tl-col-hitdt tl-sortable tl-sorted" onclick="tlToggle('${id}')">Hit / Date · Time ${sarr}</th>`;h+=`</tr></thead><tbody>`;const _rawN=exp.length>0?Math.max(...exp.map(e=>e[2])):N;show.forEach(([t,pc,hitNum],i)=>{const isLast=(hitNum===_rawN),isFirst=(hitNum===1);const rowCls=isFirst?'tl-first':isLast?'tl-last':'';const hitMark=isFirst?`<span class="tl-mark-first">${hitNum}</span>`:isLast?`<span class="tl-mark-last">${hitNum}</span>`:hitNum;h+=`<tr class="${rowCls}"><td>${pc}</td><td>${hitMark} · ${fmtDT(t)}</td></tr>`;});if(N>LIMIT){h+=`<tr class="tl-ellipsis"><td colspan="2">· · ·</td></tr>`;if(sortDesc){const[ft,fpc,fhn]=exp[N-1];h+=`<tr class="tl-first"><td>${fpc}</td><td><span class="tl-mark-first">${fhn}</span> · ${fmtDT(ft)}</td></tr>`;}else{const[lt,lpc,lhn]=exp[0];h+=`<tr class="tl-last"><td>${lpc}</td><td><span class="tl-mark-last">${lhn}</span> · ${fmtDT(lt)}</td></tr>`;}}h+='</tbody></table>';return h;}
function tlTogglePC(id){const wrap=document.getElementById('tl-'+id);if(!wrap)return;tlPCSortAsc=!tlPCSortAsc;wrap._pcSortActive=!wrap._pcSortActive;_tlRebuild(id);}
function tlChipClick(chip,rowId){const pc=chip.dataset.pc;const wrap=document.getElementById('tl-'+rowId);if(!wrap)return;if(!wrap._tlPCs)wrap._tlPCs=new Set();if(pc==='all'){wrap._tlPCs.clear();document.querySelectorAll(`#${rowId}-d .pc-chip`).forEach(c=>c.classList.add('tl-active'));}else{const allChip=document.querySelector(`#${rowId}-d .pc-chip--all`);const isAllActive=allChip&&allChip.classList.contains('tl-active');if(isAllActive){const allPCChips=Array.from(document.querySelectorAll(`#${rowId}-d .pc-chip:not(.pc-chip--all)`));allPCChips.forEach(c=>{if(c!==chip)c.classList.add('tl-active');});chip.classList.remove('tl-active');if(allChip)allChip.classList.remove('tl-active');wrap._tlPCs.clear();allPCChips.forEach(c=>{if(c.classList.contains('tl-active'))wrap._tlPCs.add(c.dataset.pc);});}else{if(wrap._tlPCs.has(pc)){if(wrap._tlPCs.size===1)return;wrap._tlPCs.delete(pc);chip.classList.remove('tl-active');}else{wrap._tlPCs.add(pc);chip.classList.add('tl-active');const total=document.querySelectorAll(`#${rowId}-d .pc-chip:not(.pc-chip--all)`).length;if(wrap._tlPCs.size===total){wrap._tlPCs.clear();document.querySelectorAll(`#${rowId}-d .pc-chip`).forEach(c=>c.classList.add('tl-active'));}}}}  _tlRebuild(rowId);}
function _tlRebuild(rowId){const wrap=document.getElementById('tl-'+rowId);if(!wrap||!wrap._rawExp)return;if(!wrap._tlPCs)wrap._tlPCs=new Set();let exp=[...wrap._rawExp];if(wrap._tlPCs.size>0){exp=exp.filter(([t,pc])=>wrap._tlPCs.has(pc));}if(wrap._pcSortActive){exp=[...exp].sort((a,b)=>{const cmp=a[1].localeCompare(b[1],undefined,{numeric:true,sensitivity:'base'});return tlPCSortAsc?cmp:-cmp;});}const N=exp.length;wrap.innerHTML=tlBuildHTML(rowId,exp,N,tlSortDesc);wrap._exp=exp;wrap._N=N;}
function renderTimeline(id,row){const wrap=document.getElementById('tl-'+id);if(!wrap)return;const raw=row.dataset.allTimestamps;if(!raw||raw==='[]'){wrap.innerHTML='<span class="dim">No timeline data</span>';return;}try{let ts=JSON.parse(raw);if(!activePCs.includes('all'))ts=ts.filter(([t,pc])=>activePCs.includes(pc));if(!ts.length){wrap.innerHTML='<span class="dim">No hits on selected PCs</span>';return;}const exp=[];ts.forEach(([t,pc,n])=>{for(let i=0;i<n;i++)exp.push([t,pc]);});const N=exp.length;const expN=exp.map((e,i)=>[e[0],e[1],N-i]);wrap._rawExp=expN;wrap._N=N;wrap._tlPCs=new Set();wrap._pcSortActive=false;wrap.innerHTML=tlBuildHTML(id,expN,N,tlSortDesc);wrap._exp=expN;document.querySelectorAll(`#${id}-d .pc-chip`).forEach(c=>c.classList.add('tl-active'));}catch(e){wrap.innerHTML='<span class="dim">Error</span>';}}
function tlToggle(id){tlSortDesc=!tlSortDesc;const wrap=document.getElementById('tl-'+id);if(wrap&&wrap._rawExp)_tlRebuild(id);}
function toggle(id){const row=document.getElementById(id),det=document.getElementById(id+'-d'),arr=document.getElementById('arr-'+id);if(!det)return;const opening=det.classList.contains('hidden');det.classList.toggle('hidden');if(arr)arr.classList.toggle('open',opening);if(opening)renderTimeline(id,row);}
function closeAllDetails(){document.querySelectorAll('#table-body tr.detail:not(.hidden)').forEach(d=>{d.classList.add('hidden');const arr=document.getElementById('arr-'+d.id.replace(/-d$/,''));if(arr)arr.classList.remove('open');});}
function qsearch(fn){window.open('https://www.google.com/search?q='+encodeURIComponent('is "'+fn+'" a system file and is it safe'),'_blank');}
function cpHash(h){if(!h||h==='—'){alert('No hash available');return;}navigator.clipboard.writeText(h).then(()=>alert('SHA256 copied!')).catch(()=>alert('Copy failed'));}
function cpPath(p){if(!p){alert('No path available');return;}navigator.clipboard.writeText(p).then(()=>alert('Path copied!')).catch(()=>alert('Copy failed'));}
function applyFilters(){const fn=document.getElementById('fname-search').value.toLowerCase();const pth=document.getElementById('path-search').value.toLowerCase();const minH=parseInt(document.getElementById('min-hits').value)||1;const minPC=parseInt(document.getElementById('min-pcs').value)||1;const fromB=dtBound('from'),toB=dtBound('to');let visible=0;document.querySelectorAll('#table-body tr.row').forEach(r=>{const pl=(r.dataset.pcList||'').split(','),ts=r.dataset.timestamp||'';const pcCount=parseInt(r.dataset.pcCount)||0;let hits=parseInt(r.dataset.totalHits)||0;if(!activePCs.includes('all')){const ph=JSON.parse(r.dataset.pcHits||'{}');hits=activePCs.reduce((s,pc)=>s+(ph[pc]||0),0);}const ok=(activePCs.includes('all')||activePCs.some(pc=>pl.includes(pc)))&&(activeExts.includes('all')||activeExts.includes(r.dataset.ext||''))&&(activePolArr.includes('all')||activePolArr.includes(r.dataset.policy||''))&&(!fn||r.dataset.filename.includes(fn))&&(!pth||r.dataset.path.includes(pth))&&(activeCat==='all'||r.dataset.cat===activeCat)&&matchDT(ts,fromB,toB)&&hits>=minH&&pcCount>=minPC;const det=document.getElementById(r.id+'-d');if(ok){r.classList.remove('hidden');visible++;}else{r.classList.add('hidden');if(det)det.classList.add('hidden');}});document.getElementById('result-count').textContent=visible+' entries';document.getElementById('empty-state').style.display=visible===0?'block':'none';updateStats();const usePag=visible>pageSize;document.getElementById('pagination').style.display=usePag?'flex':'none';if(usePag){currentPage=1;paginateRows();}}
function _pcPillCount(){return document.querySelectorAll('#pc-pills .pill:not(:first-child)').length;}
function _syncPCPills(){const allPills=document.querySelectorAll('#pc-pills .pill');if(activePCs.includes('all')){allPills.forEach(p=>p.classList.add('active'));}else{const total=_pcPillCount();allPills.forEach(p=>{const t=p.textContent.trim();if(t==='All')p.classList.toggle('active',activePCs.length===total);else p.classList.toggle('active',activePCs.includes(t));});}}
function filterPC(pc){closeAllDetails();if(pc==='all'){activePCs=['all'];}else{if(activePCs.includes('all')){const all=Array.from(document.querySelectorAll('#pc-pills .pill:not(:first-child)')).map(p=>p.textContent.trim());activePCs=all.filter(p=>p!==pc);if(!activePCs.length){activePCs=['all'];_syncPCPills();updateHitCounts();applyFilters();return;}}else if(activePCs.includes(pc)){if(activePCs.length===1)return;activePCs=activePCs.filter(p=>p!==pc);}else{activePCs.push(pc);if(activePCs.length===_pcPillCount())activePCs=['all'];}}_syncPCPills();updateHitCounts();applyFilters();}
function _pillCount(gid){return document.querySelectorAll(`#${gid} .pill:not(:first-child)`).length;}
function _syncPills(gid,arr){const isAll=arr.includes('all'),tot=_pillCount(gid);document.querySelectorAll(`#${gid} .pill`).forEach(p=>{const t=p.textContent.trim();if(t==='All')p.classList.toggle('active',isAll||arr.length===tot);else p.classList.toggle('active',isAll||arr.includes(t));});}
function filterExt(e){activeExts=['all'];_syncPills('ext-pills',activeExts);applyFilters();}
function toggleExt(e){if(activeExts.includes('all')){const all=Array.from(document.querySelectorAll('#ext-pills .pill:not(:first-child)')).map(p=>p.textContent.trim());activeExts=all.filter(x=>x!==e);if(!activeExts.length)activeExts=['all'];}else if(activeExts.includes(e)){if(activeExts.length===1)return;activeExts=activeExts.filter(x=>x!==e);if(!activeExts.length)activeExts=['all'];}else{activeExts.push(e);if(activeExts.length===_pillCount('ext-pills'))activeExts=['all'];}_syncPills('ext-pills',activeExts);applyFilters();}
function filterPol(pol){activePolArr=['all'];activePol='all';_syncPills('pol-pills',activePolArr);applyFilters();}
function togglePol(pol){if(activePolArr.includes('all')){const all=Array.from(document.querySelectorAll('#pol-pills .pill:not(:first-child)')).map(p=>p.textContent.trim());activePolArr=all.filter(x=>x!==pol);if(!activePolArr.length)activePolArr=['all'];}else if(activePolArr.includes(pol)){if(activePolArr.length===1)return;activePolArr=activePolArr.filter(x=>x!==pol);if(!activePolArr.length)activePolArr=['all'];}else{activePolArr.push(pol);if(activePolArr.length===_pillCount('pol-pills'))activePolArr=['all'];}activePol=activePolArr.includes('all')?'all':activePolArr.join('\x00');_syncPills('pol-pills',activePolArr);applyFilters();}
function filterCat(c){activeCat=c;document.querySelectorAll('.card').forEach(x=>x.classList.remove('active'));(document.getElementById('card-'+c.replace('_',''))||document.getElementById('card-all')).classList.add('active');applyFilters();}
function filterSysBlocks(){activeCat='all';document.querySelectorAll('.card').forEach(x=>x.classList.remove('active'));document.getElementById('card-blocks').classList.add('active');document.querySelectorAll('#table-body tr.row').forEach(r=>{const e=r.dataset.eventid,det=document.getElementById(r.id+'-d');if(e==='3033'||e==='3077')r.classList.remove('hidden');else{r.classList.add('hidden');if(det)det.classList.add('hidden');}});document.getElementById('result-count').textContent=document.querySelectorAll('#table-body tr.row:not(.hidden)').length+' entries';updateStats();}
function updateHitCounts(){document.querySelectorAll('#table-body tr.row').forEach(r=>{const b=r.querySelector('.hit-pill');if(!b)return;if(activePCs.includes('all')){b.textContent=r.dataset.totalHits||'0';}else{const ph=JSON.parse(r.dataset.pcHits||'{}');b.textContent=activePCs.reduce((s,pc)=>s+(ph[pc]||0),0);}});}
function updateStats(){const vis=document.querySelectorAll('#table-body tr.row:not(.hidden)');let s={tot:0,cert:0,hash:0,nc:0,blk:0};vis.forEach(r=>{s.tot++;const c=r.dataset.cat,e=r.dataset.eventid;if(c==='publisher_signed')s.cert++;else if(c==='hash_only')s.hash++;else if(c==='unknown')s.nc++;if(e==='3033'||e==='3077')s.blk++;});document.querySelector('#card-all .card-num').textContent=s.tot;document.querySelector('#card-publishersigned .card-num').textContent=s.cert;document.querySelector('#card-hashonly .card-num').textContent=s.hash;document.querySelector('#card-unknown .card-num').textContent=s.nc;document.querySelector('#card-blocks .card-num').textContent=s.blk;}
function sortTable(c){if(sortCol===c)sortDir=sortDir==='asc'?'desc':'asc';else{sortCol=c;sortDir='desc';}const tb=document.getElementById('table-body'),rows=Array.from(tb.querySelectorAll('tr.row'));rows.sort((a,b)=>{let av,bv;switch(c){case'type':av=a.dataset.cat||'';bv=b.dataset.cat||'';break;case'time':av=a.dataset.timestamp||'';bv=b.dataset.timestamp||'';break;case'file':av=a.dataset.filename||'';bv=b.dataset.filename||'';break;case'publisher':av=a.querySelector('.col-pub').textContent.trim();bv=b.querySelector('.col-pub').textContent.trim();break;case'hits':av=parseInt(a.dataset.totalHits)||0;bv=parseInt(b.dataset.totalHits)||0;break;default:return 0;}const d=sortDir==='asc'?1:-1;return av<bv?-d:(av>bv?d:0);});rows.forEach(r=>{tb.appendChild(r);const d=document.getElementById(r.id+'-d');if(d)tb.appendChild(d);});document.querySelectorAll('thead th').forEach(t=>{t.classList.remove('sorted');const a=t.querySelector('.sarr');if(a)a.textContent='';});const th=document.querySelector(`thead th[onclick*="${sortCol}"]`);if(th){th.classList.add('sorted');const a=th.querySelector('.sarr');if(a)a.textContent=sortDir==='asc'?'▴':'▾';}}
function clearCat(){activeCat='all';document.querySelectorAll('.card').forEach(x=>x.classList.remove('active'));document.getElementById('card-all').classList.add('active');applyFilters();}
function resetFilters(){document.getElementById('fname-search').value='';document.getElementById('path-search').value='';document.getElementById('min-hits').value='1';document.getElementById('min-pcs').value='1';activeExts=['all'];activeCat='all';activePol='all';activePolArr=['all'];dtAutoFill();document.querySelectorAll('.card').forEach(x=>x.classList.remove('active'));document.getElementById('card-all').classList.add('active');activePCs=['all'];_syncPCPills();_syncPills('ext-pills',activeExts);_syncPills('pol-pills',activePolArr);updateHitCounts();applyFilters();}
function paginateRows(){const vr=Array.from(document.querySelectorAll('#table-body tr.row:not(.hidden)'));totalPages=Math.max(1,Math.ceil(vr.length/pageSize));currentPage=Math.min(currentPage,totalPages);const s=(currentPage-1)*pageSize,e=s+pageSize;vr.forEach((r,i)=>{const det=document.getElementById(r.id+'-d');const show=i>=s&&i<e;r.style.display=show?'':'none';if(det)det.style.display=show?'':'none';});document.getElementById('current-page').textContent=currentPage;document.getElementById('total-pages').textContent=totalPages;['btn-first','btn-prev'].forEach(id=>document.getElementById(id).disabled=currentPage===1);['btn-next','btn-last'].forEach(id=>document.getElementById(id).disabled=currentPage===totalPages);}
function goToPage(p){currentPage=Math.max(1,Math.min(p,totalPages));paginateRows();}
function changePageSize(sel){pageSize=parseInt(sel.value);currentPage=1;paginateRows();}
function toggleColl(btn){btn.classList.toggle('open');const detail=btn.nextElementSibling;if(detail)detail.classList.toggle('hidden');}
document.addEventListener('DOMContentLoaded',()=>{BOUNDS.forEach(side=>dtRender(side));dtAutoFill();sortTable('time');updateStats();updateHitCounts();_syncPCPills();_syncPills('ext-pills',activeExts);_syncPills('pol-pills',activePolArr);});
</script>"""
