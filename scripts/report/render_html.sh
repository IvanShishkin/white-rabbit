#!/usr/bin/env bash
# White Rabbit — render a findings.json sidecar into a self-contained executive HTML report.
# STRICTLY READ-ONLY: reads one JSON file, prints HTML to stdout, writes nothing.
#   scripts/report/render_html.sh <findings.json | bundle-dir>   > report.html
#
# Deterministic: same findings.json → byte-identical HTML. All finding content is HTML-escaped
# via jq's @html (no injection). Self-contained: inline CSS/JS, no external fonts/scripts/network.
# Adopts the Houndoom report design system (near-black, hairline borders, severity tokens,
# dark-first + light toggle). Exit 0 ok / 1 invalid JSON / 2 unreadable input or no jq.
set -uo pipefail

IN="${1:-}"
# A bundle directory resolves to its findings.json.
if [ -n "$IN" ] && [ -d "$IN" ]; then IN="$IN/findings.json"; fi
if [ -z "$IN" ] || [ ! -r "$IN" ]; then
  printf 'render_html: input not readable or missing: %s\n' "${1:-<empty>}" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'render_html: jq not found\n' >&2
  exit 2
fi
if ! jq -e . "$IN" >/dev/null 2>&1; then
  printf 'render_html: not valid JSON: %s\n' "$IN" >&2
  exit 1
fi

# --- document head + stylesheet (static; the Houndoom design system) ---
cat <<'HTMLHEAD'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>White Rabbit — Security Audit</title>
<style>
:root{
  --bg:#000;--panel:#0a0a0a;--panel-2:#0e0e0e;--elev:#171717;
  --text:#ededed;--text-2:#a1a1a1;--text-3:#6f6f6f;
  --border:#1f1f1f;--border-2:#2e2e2e;--code-fg:#cfcfcf;
  --critical:#ff5a5f;--high:#ff990a;--medium:#e8c33d;--low:#34d399;--info:#3b9eff;
  --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
}
@media (prefers-color-scheme: light){
  :root{
    --bg:#fff;--panel:#fafafa;--panel-2:#f6f6f6;--elev:#efefef;
    --text:#171717;--text-2:#525252;--text-3:#8a8a8a;
    --border:#eaeaea;--border-2:#dcdcdc;--code-fg:#333;
    --critical:#dc2626;--high:#ea580c;--medium:#b78103;--low:#16a34a;--info:#2563eb;
  }
}
:root[data-theme="dark"]{
  --bg:#000;--panel:#0a0a0a;--panel-2:#0e0e0e;--elev:#171717;--text:#ededed;--text-2:#a1a1a1;--text-3:#6f6f6f;
  --border:#1f1f1f;--border-2:#2e2e2e;--code-fg:#cfcfcf;
  --critical:#ff5a5f;--high:#ff990a;--medium:#e8c33d;--low:#34d399;--info:#3b9eff;
}
:root[data-theme="light"]{
  --bg:#fff;--panel:#fafafa;--panel-2:#f6f6f6;--elev:#efefef;--text:#171717;--text-2:#525252;--text-3:#8a8a8a;
  --border:#eaeaea;--border-2:#dcdcdc;--code-fg:#333;
  --critical:#dc2626;--high:#ea580c;--medium:#b78103;--low:#16a34a;--info:#2563eb;
}
*{margin:0;padding:0;box-sizing:border-box}
html{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
body{font-family:var(--sans);background:var(--bg);color:var(--text);line-height:1.5;letter-spacing:-0.011em;padding:80px 24px 64px;transition:background .2s,color .2s}
.container{max-width:720px;margin:0 auto}
::selection{background:var(--text);color:var(--bg)}
.top{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:40px}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--text-3);margin-bottom:12px}
h1{font-size:24px;font-weight:600;letter-spacing:-0.03em;line-height:1.1;margin-bottom:10px}
.sub{font-family:var(--mono);font-size:12.5px;color:var(--text-3);line-height:1.7}
.theme-toggle{appearance:none;width:34px;height:34px;flex-shrink:0;display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--border-2);background:transparent;color:var(--text-2);border-radius:8px;cursor:pointer;font-size:14px;transition:all .15s}
.theme-toggle:hover{border-color:var(--text-3);color:var(--text)}
.thesis{font-size:15px;line-height:1.6;color:var(--text-2);margin-bottom:32px}
.thesis b{color:var(--text);font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:48px}
.kpi{background:var(--bg);padding:16px 14px}
.kpi .v{font-size:26px;font-weight:600;letter-spacing:-0.03em;font-variant-numeric:tabular-nums;line-height:1}
.kpi .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-3);margin-top:8px}
.kpi.c .v{color:var(--critical)}.kpi.h .v{color:var(--high)}.kpi.m .v{color:var(--medium)}.kpi.l0 .v{color:var(--low)}.kpi.i .v{color:var(--info)}
.finding{padding:26px 0;border-top:1px solid var(--border)}
.finding:first-of-type{border-top:none}
.frow{display:flex;align-items:center;gap:11px;margin-bottom:12px}
.sev{font-family:var(--mono);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--sv);white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.sev::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--sv)}
.finding.critical{--sv:var(--critical)}.finding.high{--sv:var(--high)}.finding.medium{--sv:var(--medium)}.finding.low{--sv:var(--low)}.finding.info{--sv:var(--info)}
.area{font-family:var(--mono);font-size:11px;color:var(--text-3);margin-left:auto}
h2{font-size:16px;font-weight:600;letter-spacing:-0.015em;line-height:1.35;margin-bottom:10px}
.why{font-size:14px;color:var(--text-2);line-height:1.6;margin-bottom:14px}
.ev{font-family:var(--mono);font-size:12px;line-height:1.7;color:var(--code-fg);background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:11px 14px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin-bottom:12px}
.fix{font-family:var(--mono);font-size:12px;line-height:1.6;color:var(--text-2)}
.fix b{color:var(--text-3);font-weight:500;margin-right:8px}
.mitre{font-family:var(--mono);font-size:11px;color:var(--text-3);margin-top:8px}
.foot{margin-top:56px;padding-top:22px;border-top:1px solid var(--border);font-family:var(--mono);font-size:11.5px;letter-spacing:.04em;color:var(--text-3)}
.foot b{color:var(--text-2);font-weight:600}
</style>
</head>
<body>
<div class="container">
HTMLHEAD

# --- dynamic body from findings.json (all values HTML-escaped via @html) ---
jq -r '
  def ord:    {critical:0,high:1,medium:2,low:3,info:4}[.severity];
  def slabel: {critical:"Critical",high:"High",medium:"Medium",low:"Low",info:"Info"}[.severity];
  def kpi($cls;$n;$lab): "<div class=\"kpi \($cls)\"><div class=\"v\">\($n)</div><div class=\"l\">\($lab)</div></div>";
  [
    "<div class=\"top\"><div>",
    "<div class=\"eyebrow\">White Rabbit · read-only audit</div>",
    "<h1>\((.host // .target) | @html)</h1>",
    "<div class=\"sub\">\([.target, .os, .collected] | map(select(. != null and . != "") | @html) | join(" · "))</div>",
    "</div><button class=\"theme-toggle\" aria-label=\"Theme\" onclick=\"toggleTheme()\">&#9790;</button></div>",
    (if (.headline // "") != "" then "<p class=\"thesis\">\(.headline | @html)</p>" else empty end),
    "<div class=\"kpis\">",
    kpi("c";  .summary.critical; "Crit"),
    kpi("h";  .summary.high;     "High"),
    kpi("m";  .summary.medium;   "Med"),
    kpi("l0"; .summary.low;      "Low"),
    kpi("i";  .summary.info;     "Info"),
    "</div>",
    ( .findings | sort_by(ord) | .[] |
        "<div class=\"finding \(.severity)\">"
      + "<div class=\"frow\"><span class=\"sev\">\(slabel)</span><span class=\"area\">\(.area | @html)</span></div>"
      + "<h2>\(.title | @html)</h2>"
      + "<p class=\"why\">\(.why | @html)</p>"
      + "<div class=\"ev\">\(.evidence | map(@html) | join("\n"))</div>"
      + "<div class=\"fix\"><b>\(if .severity == "info" then "note" else "fix" end)</b>\(.fix | @html)</div>"
      + (if (.mitre // "") != "" then "<div class=\"mitre\">MITRE \(.mitre | @html)</div>" else "" end)
      + "</div>"
    ),
    "<div class=\"foot\"><p>Generated by <b>White Rabbit</b> · \(.collected | @html)</p></div>"
  ] | .[]
' "$IN"

# --- theme toggle + close (static) ---
cat <<'HTMLTAIL'
</div>
<script>
function toggleTheme(){
  var r=document.documentElement,cur=r.getAttribute('data-theme');
  if(!cur){cur=window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';}
  var next=cur==='light'?'dark':'light';
  r.setAttribute('data-theme',next);
  var b=document.querySelector('.theme-toggle');if(b)b.innerHTML=next==='light'?'☀':'☾';
}
</script>
</body>
</html>
HTMLTAIL
