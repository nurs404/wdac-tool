"""
data/_ps_snippet.py
===================
Embedded PowerShell snippet sent to each remote PC by remote_handler.py.

The snippet runs *on the remote machine* and does one thing:
query Microsoft-Windows-CodeIntegrity/Operational for WDAC events,
parse each event's XML to extract named Data fields (never positional
Properties[]), and print the result as compact JSON to stdout.

Python reads stdout, parses the JSON, and writes the CSV.

Notes
-----
- Uses $ev.ToXml() + [xml] cast to iterate Data elements by .Name attr.
  This is the only reliable method: $ev.Properties[] gives an anonymous
  positional array whose indices differ across Windows versions / policies.
- ConvertTo-Json returns a plain object (not array) when only 1 event.
  remote_handler.py normalises this edge case.
- $MaxEvents and $DaysBack are injected as PS variable definitions
  prepended to the snippet by build_snippet().
- OutputColumns list must stay in sync with OUTPUT_COLUMNS in
  remote_handler.py.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Raw PowerShell body — NO variable definitions here; injected by build_snippet
# ---------------------------------------------------------------------------
_SNIPPET_BODY = r"""
$ErrorActionPreference = 'SilentlyContinue'

# ── Step 1: collect block/audit events (3076, 3077, 3033, 3034) ──────────────
$filter = @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = @(3076, 3077, 3033, 3034)
    StartTime = (Get-Date).AddDays(-$DaysBack)
}
$blockEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents `
               -ErrorAction SilentlyContinue

if (-not $blockEvents) { '[]'; exit 0 }

# ── Step 2: collect correlated signature events (3089) ───────────────────────
# 3089 carries Publisher and Issuer. It is linked to its parent block event
# via a shared ActivityID in the System section. We fetch ALL 3089 events in
# the same time window and build a lookup: ActivityID -> Publisher/Issuer.
# Using the FIRST 3089 per ActivityID that has a non-empty Publisher.
$sigFilter = @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = @(3089)
    StartTime = (Get-Date).AddDays(-$DaysBack)
}
$sigEvents = Get-WinEvent -FilterHashtable $sigFilter -MaxEvents ($MaxEvents * 4) `
             -ErrorAction SilentlyContinue

# Build ActivityID -> {Publisher, Issuer} map
$sigMap = @{}
if ($sigEvents) {
    foreach ($se in $sigEvents) {
        $actId = $se.ActivityId
        if (-not $actId) { continue }
        $key = $actId.ToString()
        if ($sigMap.ContainsKey($key)) { continue }   # already have one
        $sx = [xml]$se.ToXml()
        $sd = @{}
        foreach ($node in $sx.Event.EventData.Data) {
            $sd[$node.Name] = $node.'#text'
        }
        $pub = $sd['PublisherTBSHash']     # fallback field name variant
        if (-not $pub) { $pub = $sd['Publisher'] }
        $iss = $sd['IssuerTBSHash']
        if (-not $iss) { $iss = $sd['Issuer'] }
        if ($pub -or $iss) {
            $sigMap[$key] = @{ Publisher = $pub; Issuer = $iss }
        }
    }
}

# ── Step 3: build output rows ────────────────────────────────────────────────
$rows = foreach ($ev in $blockEvents) {
    $xml = [xml]$ev.ToXml()
    $d   = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $d[$node.Name] = $node.'#text'
    }

    # Resolve Publisher: prefer inline field, fall back to 3089 join
    $publisher = $d['Publisher']
    $issuer    = $d['Issuer']
    if ((-not $publisher) -and $ev.ActivityId) {
        $key = $ev.ActivityId.ToString()
        if ($sigMap.ContainsKey($key)) {
            $publisher = $sigMap[$key].Publisher
            $issuer    = $sigMap[$key].Issuer
        }
    }

    [PSCustomObject]@{
        TimeCreated           = $ev.TimeCreated.ToString('dd.MM.yyyy HH:mm:ss')
        EventID               = [string]$ev.Id
        MachineName           = $ev.MachineName
        FilePath              = $d['File Name']
        ProcessName           = $d['Process Name']
        RequestedSigningLevel = $d['Requested Signing Level']
        ValidatedSigningLevel = $d['Validated Signing Level']
        PolicyName            = $d['Policy Name']
        PolicyGUID            = $d['PolicyGUID']
        SHA1FlatHash          = $d['SHA1 Flat Hash']
        SHA256FlatHash        = $d['SHA256 Flat Hash']
        Publisher             = $publisher
        Issuer                = $issuer
        OriginalFilename      = $d['OriginalFilename']
        InternalName          = $d['InternalName']
        SISigningScenario     = $d['SI Signing Scenario']
    }
}

$rows | ConvertTo-Json -Compress -Depth 2
"""


def build_snippet(max_events: int = 5000, days_back: int = 30) -> str:
    """
    Return a compressed, self-decompressing PS bootstrap that wraps the
    full snippet.  Sent verbatim to session.run_ps() by remote_handler.

    Why compression?
    pywinrm's run_ps() base64-encodes the script into UTF-16LE and passes
    it as -EncodedCommand.  The full script (~3.5 KB) produces a ~9300-char
    command line, exceeding cmd.exe's hard 8191-char limit and causing
    "The command line is too long" on every PC.

    Gzip compression shrinks the script to ~35% (≈1.3 KB).  The bootstrap
    wrapper is always ~300 chars, giving a final command line of ~5300
    chars — comfortably within the limit regardless of script size.
    """
    import gzip
    import base64

    header = (
        f"$MaxEvents = {int(max_events)}\n"
        f"$DaysBack  = {int(days_back)}\n"
    )
    full_script = header + _SNIPPET_BODY

    compressed = gzip.compress(full_script.encode('utf-8'), compresslevel=9)
    b64 = base64.b64encode(compressed).decode('ascii')

    # 5-line PS bootstrap: decode → decompress → execute
    bootstrap = (
        f"$b=[Convert]::FromBase64String('{b64}')\n"
        "$ms=New-Object IO.MemoryStream(,$b)\n"
        "$gs=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress)\n"
        "$sr=New-Object IO.StreamReader($gs,[Text.Encoding]::UTF8)\n"
        "Invoke-Expression $sr.ReadToEnd()"
    )
    return bootstrap