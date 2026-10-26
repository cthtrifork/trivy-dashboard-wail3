# UX design sheet

One page describing how the UI looks and behaves, so new screens and components stay consistent. It documents what `frontend/src/style.css` and the components do today; when they change, change this sheet in the same PR. Screenshots live in `docs/screenshots/`.

## Design intent

- **Shortlist first.** The first screen answers "what do I act on?" (decision: fewer, better findings, `docs/principles.md` #7). Detail is one click away, never in the way.
- **Every number is explainable.** A score, tier or rank always has its reason next to it (`Score 41 · why`).
- **Dense but calm.** A working tool: small type, tight spacing, color only where it carries meaning (severity, tier, state).
- **Light and dark** follow the OS (`prefers-color-scheme`); there is no manual toggle.

## Layout

```
┌ header ───────────────────────────────────────────────┐
│ [ image reference .................... ] [Scan] Options ▸ (?) │
│ meta line: image · OS                                 │
├ banner (demo mode only) ──────────────────────────────┤
├ tabs: Priorities · Vulnerabilities · Dependencies · SBOM · Compare ........ Log ┤
├ panel (one visible, scrolls internally) ──────────────┤
├ status line (scan progress / errors) ─────────────────┤
└ footprint line ───────────────────────────────────────┘
```

- Single window, no routing. The active tab is one `ref`; panels stay mounted and are shown/hidden, so filters and scroll survive tab switches.
- Header: monospace image input grows to fill; **Scan** is disabled while a scan runs and a red **Cancel** appears next to it. Secondary settings sit in the **Options** popover (260 px wide, right-aligned). **?** opens Help (glossary, configuration).
- Tabs carry count badges (findings that need attention, vulnerabilities, components). **Log** is pushed to the far right because it is diagnostic.
- Panels use 12 px / 16 px padding and a 12 px gap between blocks.

## Tokens

Defined as CSS custom properties on `:root` in `frontend/src/style.css`.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#0f1218` | `#f6f7f9` | page, inputs |
| `--panel` | `#161b24` | `#ffffff` | header, cards, popovers |
| `--line` | `#262d3a` | `#dde1e8` | borders, badge fill |
| `--text` | `#dde3ee` | `#1c2330` | body text |
| `--mute` | `#8b95a7` | `#5e6878` | secondary text, labels |
| `--accent` | `#4c8dff` | same | primary action, links, focus, active tab |
| `--ok` | `#3fb97a` | `#1a7f45` | success, resolved |

Severity (same in both themes): `--CRITICAL #e5484d`, `--HIGH #f76b15`, `--MEDIUM #f5b800`, `--LOW #3e9bd6`, `--UNKNOWN #7b8494`.

Tier colors reuse the severity palette so urgency reads the same everywhere:

| Tier | Color | Meaning |
|---|---|---|
| Act now | `--CRITICAL` | exploited or near-certain |
| Fix soon | `--HIGH` | |
| Plan | `--MEDIUM` | |
| Monitor | `--UNKNOWN` | low risk, hidden by default |

Rules: never use a new hex in a component, add a token. Color is never the only signal: severity and tier always have a text label.

## Typography and spacing

- Body `14px / 1.4 system-ui`. Small/meta text 12 px in `--mute`. Stat numbers 22 px bold. Card labels 12 px uppercase, `0.04em` tracking.
- Monospace (`ui-monospace`) for anything copied or compared literally: image references, package names and versions, CVE-adjacent identifiers.
- Spacing steps in use: 4, 8, 12, 16. Radius 6 px for controls, 8 px for cards and popovers, 10 px for badges and chips (badges 12 px text, chips 11 px).
- Popover shadow `0 8px 24px #0006`. No other shadows.

## Components

| Component | Pattern | Notes |
|---|---|---|
| Primary button | solid `--accent`, white text, 6 px radius | one per region; disabled = 50% opacity |
| Destructive button | solid `--CRITICAL` | Cancel only |
| Ghost button | text on transparent | Help, Options actions, dismissals |
| Dashed button | dashed border, `+` prefix | adds something optional (Add VEX assessment) |
| Input | `--bg` fill, 1 px `--line`, 2 px `--accent` focus ring (inset) | |
| Tab | text button, 2 px bottom border; active = `--text` + `--accent` underline | |
| Badge | `--line` pill with count | |
| Stat card | 4 px left border in tier/severity color, big number over uppercase label | clickable; `off` = 40% opacity when its filter is disabled |
| Chip | outlined pill, 11 px, `--mute` text; kinds: `hot` (solid red, KEV), `warm` (orange outline: EPSS ≥ 10%, network vector, expired VEX), `vex` (accent outline, VEX status) | facts about a finding: severity + CVSS, KEV, EPSS, attack vector, fix versions |
| Tier pill | filled pill, top right of a finding card | |
| Disclosure (`details`) | `▸` summary in `--mute` | Scoring rules, Score · why, Suppressed by VEX (n), Options |
| Banner | full-width strip under the header | demo mode warning only |

### Finding row (Priorities)

Findings are table rows, not cards, so a long list stays scannable. Two segmented filters above the list (Severity, Priority; each segment shows a count that respects the other filter) narrow it; an empty selection means "all". Picking a Priority by hand overrides "Include low-risk", so choosing Monitor shows Monitor.

Collapsed row, left to right:

1. Severity stripe (CVSS severity colour) and severity pill
2. CVSS score with a 0 to 10 meter in the same colour
3. Title (bold), then `#n`, CVE link (accent, opens the advisory) and package and version (monospace)
4. Priority tier with its colour square, and a KEV chip when listed
5. Fix versions, or "None"

Clicking the row (or Enter on the title button) expands it, from "what is it" to "what should I do":

1. Chips: ransomware use, EPSS, attack vector, fix versions (or "No fix yet"), VEX status
2. **What it means**: one plain-language paragraph on a tinted band; says when the finding only matters (running and reachable)
3. `Score N · why` disclosure listing each fired rule with its points
4. VEX box: dashed `+ Add VEX assessment` chip, which becomes a status chip once assessed

The reasoning stays collapsed until asked for. Below 760 px the header row is hidden and each row stacks.

## Tabs

Observed by running the headless server in demo mode (`TRIVY_SCANNER_FAKE_PODMAN=1`) at 1400×900, dark and light, driven with Playwright.

| Tab | Top to bottom |
|---|---|
| Priorities | Severity and Priority segmented filters with counts, Scoring rules disclosure, toolbar (Show top 10/25/all, Hide resolved by VEX, Include low-risk, Only with a fix, effect summary), one-line ranking note, column header row (Severity, CVSS, Finding, Priority, Fix; each with an explanatory tooltip) and finding rows |
| Vulnerabilities | severity stat cards (Critical → Unknown) that double as filters, text filter plus "n shown", sortable table with explanatory header tooltips: Priority (tier pill), Severity, ID, Package, Installed, Fixed in, CVSS (number plus bar), EPSS, Signals, Title; rows expand for details |
| Dependencies | search, All / OS / Application segmented control, Vulnerable paths only, Focus select, All labels, Fit, "n of N components"; canvas graph with legend and a right-hand inspector ("Click a node to inspect it."). Node color = kind, orange ring = vulnerable via dependency, size = vulnerability count. Scroll zooms, drag pans, double-click fits |
| SBOM | one-sentence summary of the image, type stat cards (accent border, not severity colors), filter plus format ("CycloneDX"), sortable table: Name, Version, Type, License, Package URL |
| Compare | image, Base tag, Target tag, Load tags, Compare; centered hint until a comparison runs |
| Log | monospace scan log in a bordered panel, fills the height; the only tab pushed right |

Stat cards come in two colorings: severity colors (Vulnerabilities) and accent (SBOM). Priorities uses segmented filters instead.

Interactions checked by running them:

- **Vulnerabilities**: clicking a row expands it in place (what it means, target, status, description, advisory link, Add VEX assessment); the text filter and the severity cards combine, and a toggled-off card dims (`off`) and updates "n shown".
- **Dependencies**: clicking a node dims the rest of the graph, highlights its edges, and fills the inspector (vulnerability counts by severity, Depends on, Required by); a caption above the canvas names the selection.
- **Compare**: Base and Target summary cards with per-severity deltas (green when lower), a green verdict banner ("The target is better: ..."), a Vulnerabilities / Packages segmented control, added/removed/unchanged filters with `+` `-` `=` glyph badges, and a diff table.
- **VEX drawer**: modal docked to the right; header with CVE, severity chip, tier chip and "Full advisory"; plain-language summary with four facts (Attack from, Needs, Impact, Fix); "Applies to" list with Select all; four status buttons; Cancel (ghost) and Save assessment (disabled until a status is chosen).
- **Help**: centered modal with Glossary and App config tabs.

Options popover contents: Ignore unfixed, registry username, registry password/token, Trivy version or image, app version with Check for updates.

## Known inconsistencies

Found while running the UI; not fixed by this sheet.

- **Vulnerabilities CVE links use the browser default blue** (`rgb(0,0,238)`) instead of `--accent`, which is close to unreadable on the dark background. Priorities links use `--accent`. Links should share one style.
- **Options placeholder is clipped** ("Trivy version or image (default t…") at the 260 px popover width.
- **At 800 px** the demo banner wraps and the open Options popover covers the right-hand tabs. Usable.
- **At 500 px** the tab bar is clipped (Compare and Log are off-screen), the page scrolls horizontally, the Priorities toolbar overflows, and the Scoring rules card leaves a large blank gap. 700 px has no horizontal scroll.
- **Vulnerabilities links** also affected the VEX drawer (CVE link, Full advisory); both are fixed by PR #44 (`a { color: var(--accent) }`).

## Key flows

- **Scan**: type an image, Enter or Scan. Status line shows progress; Cancel is available while it runs and removes the container. Results land on Priorities.
- **Triage**: stat cards summarise tiers; toolbar filters (`Show top 10`, Hide resolved by VEX, Include low-risk, Only with a fix) re-filter without rescanning. A summary line states the effect ("29 findings → 0 worth acting on · 8 low-risk not shown").
- **Tune**: Scoring rules disclosure re-ranks immediately; the header shows the active preset name, or `custom`.
- **Record a decision**: Add VEX assessment on a card, (opens a docked drawer), then Export VEX (n) next to Scan to review and export OpenVEX. With no assessments yet that button reads Import VEX; once there are some, its dropdown offers Import / merge VEX.
- **Explore**: Vulnerabilities (filterable table, row details), Dependencies (canvas graph: select, focus, all components), SBOM list, Compare two scans.

## States

| State | Treatment |
|---|---|
| Empty (before first scan) | counts show 0 |
| Filtered to nothing | list shows "Nothing left to show with these filters." |
| Busy | status line spinner, Scan disabled, Cancel shown |
| Error | status line in error style (`.err`), message from the Go side verbatim |
| Nothing to act on | summary line says so; Monitor items stay hidden but counted |
| Demo mode | persistent banner; only in non-production builds |

## Interaction and accessibility

- Everything is keyboard reachable with a visible 2 px focus ring; icon-only controls need `aria-label` (Help has one).
- Text contrast uses `--text` on `--panel` and `--mute` only for non-essential text. Check any new token pair for 4.5:1.
- Hover titles explain badges (`findings that need attention`).
- Long lists use virtual scrolling (`lib/virtual.js`); rows may vary in height; they are measured after render (`useVirtualList`, 10 px gap), so avoid layout that changes height outside interaction or resize.
- Stat cards and the header form wrap (`flex-wrap`) when the window narrows.

## Do and don't

- Do reuse existing tokens, chips and cards before inventing a component.
- Do put the reason beside any computed value.
- Do keep new settings in a disclosure or the Options popover, not in the main flow.
- Don't add a runtime UI dependency (`docs/principles.md` #15) or a theme toggle without a decision record.
- Don't introduce a second accent color; urgency uses the severity palette only.
- Don't show fixtures or demo affordances in production builds.

## Open questions

- Below about 700 px the tab bar and toolbars have no overflow handling.
- No documented keyboard shortcuts beyond Enter to scan.
