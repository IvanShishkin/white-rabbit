# Report design reference (Reporting v2, Phase 2)

`report.sample.html` is the **design target** for the executive HTML report that
`scripts/report/render_html.sh` will generate in Phase 2. It is a static, self-contained
sample rendered from the 2026-07-10 audit of `158.160.2.43` — no external fonts, scripts,
or network.

## Design system

Adopts the **Houndoom** report design system (`IvanShishkin/houndoom`,
`internal/report/html.go` — "Vercel-style, dark default + light toggle"):

- **Tokens** — near-black ground (`#000` / panels `#0a0a0a`), hairline borders (`#1f1f1f`),
  severity `critical #ff5a5f · high #ff990a · medium #e8c33d · low #34d399 · info #3b9eff`;
  light theme mirrors Houndoom's (`#dc2626 / #ea580c / …`).
- **Type** — Inter + JetBrains Mono (system fallbacks under the artifact CSP), tabular-nums,
  uppercase mono micro-labels.
- **Theme** — dark-first, respects the viewer's `prefers-color-scheme`, with a manual toggle.

## Layout

Deliberately minimal (Vercel restraint): a 720px column, a one-line thesis, a severity KPI
grid, and a hairline-divided findings list (severity dot + area, title, one-line why,
evidence, fix). No decorative section chrome. Signature only in the footer.

## Phase 2 (not yet built)

`render_html.sh <bundle-dir>/findings.json` will template this markup from the structured
sidecar so any audit renders to `report.html` deterministically. This file is the reference
the generator must reproduce.
