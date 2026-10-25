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
- Header: monospace image input grows to fill; **Scan** turns into a red **Cancel** while a scan runs. Secondary settings sit in the **Options** popover (260 px wide, right-aligned). **?** opens Help (glossary, configuration).
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
- Spacing steps in use: 4, 8, 12, 16. Radius 6 px for controls, 8 px for cards and popovers, 10 px for badges and chips.
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
| Chip | outlined pill, 12 px | facts about a finding: severity + CVSS, attack vector, fix versions |
| Tier pill | filled pill, top right of a finding card | |
| Disclosure (`details`) | `▸` summary in `--mute` | Scoring rules, Score · why, Options |
| Banner | full-width strip under the header | demo mode warning only |

### Finding card (Priorities)

1. Rank `#n` and CVE link (accent, opens the advisory) · tier pill right-aligned
2. Title (bold)
3. Package and version (monospace)
4. Chips: severity + CVSS, attack vector, fix versions
5. **What it means**: one plain-language paragraph on a tinted band; says when the finding only matters (running and reachable)
6. `Score N · why` disclosure listing each fired rule with its points
7. `+ Add VEX assessment`

Order inside the card goes from "what is it" to "what should I do", and the reasoning stays collapsed until asked for.

## Key flows

- **Scan**: type an image, Enter or Scan. Status line shows progress; Cancel is always available and removes the container. Results land on Priorities.
- **Triage**: stat cards summarise tiers; toolbar filters (`Show top 10`, Hide resolved by VEX, Include low-risk, Only with a fix) re-filter without rescanning. A summary line states the effect ("29 findings → 0 worth acting on · 8 low-risk not shown").
- **Tune**: Scoring rules disclosure re-ranks immediately; the header shows the active preset name, or `custom`.
- **Record a decision**: Add VEX assessment on a card, then Edit/Create VEX (n) to review and export OpenVEX.
- **Explore**: Vulnerabilities (filterable table, row details), Dependencies (canvas graph: select, focus, all components), SBOM list, Compare two scans.

## States

| State | Treatment |
|---|---|
| Empty (before first scan) | counts show 0 |
| Busy | status line spinner, Scan replaced by Cancel |
| Error | status line in error style (`.err`), message from the Go side verbatim |
| Nothing to act on | summary line says so; Monitor items stay hidden but counted |
| Demo mode | persistent banner; only in non-production builds |

## Interaction and accessibility

- Everything is keyboard reachable with a visible 2 px focus ring; icon-only controls need `aria-label` (Help has one).
- Text contrast uses `--text` on `--panel` and `--mute` only for non-essential text. Check any new token pair for 4.5:1.
- Hover titles explain badges (`findings that need attention`).
- Long lists use virtual scrolling (`lib/virtual.js`); keep row heights fixed so it keeps working.
- Stat cards and the header form wrap (`flex-wrap`) when the window narrows.

## Do and don't

- Do reuse existing tokens, chips and cards before inventing a component.
- Do put the reason beside any computed value.
- Do keep new settings in a disclosure or the Options popover, not in the main flow.
- Don't add a runtime UI dependency (`docs/principles.md` #15) or a theme toggle without a decision record.
- Don't introduce a second accent color; urgency uses the severity palette only.
- Don't show fixtures or demo affordances in production builds.

## Open questions

- Narrow-window (< 900 px) layout is untested; the tab bar has no overflow handling.
- No documented keyboard shortcuts beyond Enter to scan.
