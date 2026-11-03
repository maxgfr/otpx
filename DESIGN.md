---
name: otpx
description: 2FA codes from an encrypted vault you keep, on neutral zinc cards with one blue accent.
colors:
  # Light scheme (default). Source of truth: web/static/app.css :root
  ground: "#fafafa"
  fg: "#18181b"
  fg-2: "#52525b"
  rule: "#e4e4e7"
  surface: "#ffffff"
  edge: "#e4e4e7"
  ink: "#18181b"
  ink-2: "#52525b"
  field: "#ffffff"
  field-edge: "#d4d4d8"
  hover: "#f4f4f5"
  bar: "#18181b"
  bar-2: "#27272a"
  on-bar: "#fafafa"
  on-bar-2: "#a1a1aa"
  invert: "#18181b"
  invert-2: "#3f3f46"
  on-invert: "#fafafa"
  on-invert-2: "#a1a1aa"
  accent: "#2563eb"
  accent-hover: "#1d4ed8"
  on-accent: "#ffffff"
  accent-line: "#2563eb"
  accent-soft: "#dbeafe"
  accent-ink: "#1d4ed8"
  warn-soft: "#fffbeb"
  warn-edge: "#f59e0b"
  star: "#f59e0b"
  star-edge: "#b45309"
  danger: "#dc2626"
  danger-soft: "#fef2f2"
  danger-ink: "#b91c1c"
  danger-fill: "#dc2626"
  hole: "#f4f4f5"
  focus: "#2563eb"
  focus-bar: "#60a5fa"
  # Dark scheme (prefers-color-scheme: dark). Tokens not listed keep their light value.
  ground-dark: "#09090b"
  fg-dark: "#fafafa"
  fg-2-dark: "#a1a1aa"
  rule-dark: "#27272a"
  surface-dark: "#18181b"
  edge-dark: "#27272a"
  ink-dark: "#fafafa"
  ink-2-dark: "#a1a1aa"
  field-dark: "#09090b"
  field-edge-dark: "#3f3f46"
  hover-dark: "#27272a"
  invert-dark: "#fafafa"
  invert-2-dark: "#e4e4e7"
  on-invert-dark: "#18181b"
  on-invert-2-dark: "#52525b"
  accent-line-dark: "#3b82f6"
  accent-soft-dark: "#1e3a8a"
  accent-ink-dark: "#bfdbfe"
  warn-soft-dark: "#422006"
  warn-edge-dark: "#b45309"
  star-dark: "#fbbf24"
  star-edge-dark: "#d97706"
  danger-dark: "#f87171"
  danger-soft-dark: "#450a0a"
  danger-ink-dark: "#fca5a5"
  hole-dark: "#27272a"
  focus-dark: "#60a5fa"
typography:
  display:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "clamp(2rem, 6vw, 2.75rem)"
    fontWeight: 800
    lineHeight: 1.08
    letterSpacing: "-0.03em"
  code-hero:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "clamp(2.75rem, 13vw, 4.5rem)"
    fontWeight: 650
    lineHeight: 1
    letterSpacing: "0.06em"
    fontFeature: "\"tnum\" 1"
  headline:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  code:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 650
    lineHeight: 1.1
    letterSpacing: "0.05em"
    fontFeature: "\"tnum\" 1"
  title:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  brand:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 800
    letterSpacing: "0.02em"
  body:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "\"tnum\" 1"
  button:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 650
    lineHeight: 1.5
  label:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 650
    lineHeight: 1.5
  small:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  eyelet-numeral:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 650
    fontFeature: "\"tnum\" 1"
  secret:
    fontFamily: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 650
    lineHeight: 1.7
    letterSpacing: "0.06em"
  mono:
    fontFamily: "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    fontSize: "0.92em"
rounded:
  focus: "4px"
  inline-code: "5px"
  control: "9px"
  plate: "12px"
  pill: "999px"
  round: "50%"
spacing:
  "0.5": "0.125rem"
  "1": "0.25rem"
  "1.5": "0.375rem"
  "2": "0.5rem"
  "2.5": "0.625rem"
  "3": "0.75rem"
  "3.5": "0.875rem"
  "4": "1rem"
  "5": "1.25rem"
  "6": "1.5rem"
  "8": "2rem"
  control-bar: "2.5rem"
  control: "2.75rem"
  bar: "3.75rem"
  measure: "46rem"
components:
  bar:
    backgroundColor: "{colors.bar}"
    textColor: "{colors.on-bar}"
    height: "{spacing.bar}"
    padding: "0.625rem 1rem"
  bar-search:
    backgroundColor: "{colors.bar-2}"
    textColor: "{colors.on-bar}"
    rounded: "{rounded.control}"
    height: "{spacing.control-bar}"
    padding: "0 0.875rem 0 2.5rem"
  bar-button:
    textColor: "{colors.on-bar}"
    rounded: "{rounded.control}"
    typography: "{typography.small}"
    size: "{spacing.control-bar}"
  bar-button-active:
    backgroundColor: "{colors.bar-2}"
    textColor: "{colors.on-bar}"
  tag:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.plate}"
    padding: "0.75rem 0.5rem 0.75rem 0.875rem"
  tag-copied:
    backgroundColor: "{colors.invert}"
    textColor: "{colors.on-invert}"
    rounded: "{rounded.plate}"
  tag-big:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.plate}"
    padding: "1.5rem"
  eyelet:
    backgroundColor: "{colors.accent-line}"
    rounded: "{rounded.round}"
    size: "2.5rem"
  eyelet-ending:
    backgroundColor: "{colors.danger}"
    rounded: "{rounded.round}"
    size: "2.5rem"
  eyelet-hole:
    backgroundColor: "{colors.hole}"
    textColor: "{colors.fg-2}"
    rounded: "{rounded.round}"
    typography: "{typography.eyelet-numeral}"
    size: "1.875rem"
  eyelet-big:
    backgroundColor: "{colors.accent-line}"
    rounded: "{rounded.round}"
    size: "3.5rem"
  plate:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.plate}"
    padding: "1.25rem"
  choice:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.plate}"
    padding: "0.875rem 1rem"
  button-plain:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    typography: "{typography.button}"
    height: "{spacing.control}"
    padding: "0 1rem"
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.control}"
    typography: "{typography.button}"
    height: "{spacing.control}"
    padding: "0 1rem"
  button-danger:
    textColor: "{colors.danger}"
    rounded: "{rounded.control}"
    typography: "{typography.button}"
    height: "{spacing.control}"
    padding: "0 1rem"
  button-danger-hover:
    backgroundColor: "{colors.danger-soft}"
    textColor: "{colors.danger}"
  button-quiet:
    typography: "{typography.body}"
    height: "{spacing.control}"
    padding: "0 1rem"
  field:
    backgroundColor: "{colors.field}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    typography: "{typography.body}"
    height: "{spacing.control}"
    padding: "0.5rem 0.75rem"
  notice-proof:
    textColor: "{colors.fg-2}"
    rounded: "{rounded.control}"
    typography: "{typography.small}"
    padding: "0.75rem 0.875rem"
  notice-warn:
    backgroundColor: "{colors.warn-soft}"
    textColor: "{colors.fg}"
    rounded: "{rounded.control}"
    typography: "{typography.small}"
    padding: "0.75rem 0.875rem"
  notice-error:
    backgroundColor: "{colors.danger-soft}"
    textColor: "{colors.fg}"
    rounded: "{rounded.control}"
    typography: "{typography.small}"
    padding: "0.75rem 0.875rem"
  tabs:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.plate}"
    padding: "0.25rem"
  tab:
    textColor: "{colors.ink-2}"
    rounded: "{rounded.control}"
    typography: "{typography.label}"
    height: "{spacing.control-bar}"
  tab-selected:
    backgroundColor: "{colors.invert}"
    textColor: "{colors.on-invert}"
    rounded: "{rounded.control}"
  toast:
    backgroundColor: "{colors.invert}"
    textColor: "{colors.on-invert}"
    rounded: "{rounded.control}"
    padding: "0.75rem 1rem"
  toast-error:
    backgroundColor: "{colors.danger-fill}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.control}"
    padding: "0.75rem 1rem"
  chip:
    textColor: "{colors.fg-2}"
    rounded: "{rounded.pill}"
    typography: "{typography.small}"
    padding: "0.125rem 0.625rem"
---

# Design System: otpx

## Overview

**North Star: "A quiet utility"**

otpx looks like the platform's own tools: neutral zinc greys, white cards, one blue accent. Each account is a card in a single ordered column; its code is set large in heavy tabular figures. A near-black top bar frames the app in both schemes. The system is built for operating, not browsing: one column at most 46rem wide, search one keystroke away, a tap to copy, and nothing ornamental competing with the code.

Colour is flat and conventional. Blue is the single accent: the countdown arc, the primary action, link underlines, the caret, focus rings. Red appears only for destruction, errors and the last five seconds of a code; amber only for warnings and the favourite star. Hierarchy comes from weight and inversion (a copied card, the selected tab and the toast swap to the inverted tone) rather than from extra sizes or colours. Dark mode is a true dark scheme: zinc-black ground, dark cards, dark fields.

The owner asked for sobriety: no gradients, no decorative imagery, no shadows used as styling. Every line that tells the user where a secret goes sits beside its action as a plain notice.

**Key Characteristics:**
- One centered column of white cards on an off-white ground (light) or zinc cards on near-black (dark), max 46rem.
- Zinc neutrals everywhere; blue is the one accent; red is reserved for danger and expiry; amber for warnings.
- The countdown ring around each account: a blue arc that depletes with the code's remaining time, with the seconds in the middle.
- Codes in heavy tabular figures, grouped in threes or fours, with wide tracking.
- System UI sans throughout, by decision; rank by weight and inversion.
- Flat surfaces separated by a 1px edge; the toast is the only floating element.

## Colors

A neutral zinc scale with a blue accent, red for loss and amber for warnings, set as hex tokens and re-tuned for dark rather than inverted.

### Neutral
- **Ground** (`ground`): page background, `#fafafa`; dark `#09090b`.
- **Ground Ink** (`fg`) and **Ground Ink Muted** (`fg-2`): text set directly on the ground: headings, leads, hints, meta lines, back links, proof notices.
- **Rule** (`rule`): hairline dividers on the ground: proof-notice border, chip outline, danger-zone rule, scrollbar thumb.
- **Surface** (`surface`): every card: list items, the big account card, form plates, the unlock card, choices, remotes, the tab strip, plain buttons. White in light, zinc-900 in dark.
- **Edge** (`edge`): the 1px edge of every card, the chevron divider, the empty part of the countdown ring.
- **Ink** (`ink`) and **Ink Muted** (`ink-2`): text on cards.
- **Field** (`field`) with **Field Edge** (`field-edge`): inputs, textareas and selects; darker than the card in dark mode.
- **Hover** (`hover`): hover fill of cards, choices and plain buttons.
- **Hole** (`hole`): the centre of the countdown ring, holding the seconds.

### Shell
- **Bar** (`bar`, `bar-2`, `on-bar`, `on-bar-2`): the sticky top bar in zinc-900 for both schemes, its search well and button hover in zinc-800, text in zinc-50 and muted zinc-400.
- **Invert** (`invert`, `invert-2`, `on-invert`, `on-invert-2`): the reversed state: a copied card, the selected tab, the toast. Zinc-900 on light, zinc-50 on dark, so the reversal always reads.

### Accent
- **Blue** (`accent`, `accent-hover`, `on-accent`): the primary button fill (blue-600, white text, 5.2:1), its hover in blue-700, checkbox accent and the caret.
- **Blue Line** (`accent-line`): the countdown arc and link underlines; blue-500 in dark to hold contrast on dark cards.
- **Blue Wash** (`accent-soft`, `accent-ink`): text selection and the round icon badge on start choices.
- **Focus** (`focus`, `focus-bar`): 2px rings in blue-600 on light, blue-400 on dark and in the bar.

### Status
- **Red** (`danger`, `danger-soft`, `danger-ink`, `danger-fill`): destructive buttons, error notices, the ending countdown arc and numeral, and the error toast (always on red-600 with white text).
- **Amber** (`warn-soft`, `warn-edge`, `star`, `star-edge`): warning notices (the QR "it holds the secret" line, risk notes) and the favourite star.

### Named Rules
**The One Accent Rule.** Blue marks the primary action of a group, the countdown, links and focus. It never fills a card, a heading or a background region larger than a button.

**The Red Means Loss Rule.** Red marks only what destroys, fails, or is about to expire. A red element that is none of these is a bug.

**The Inversion Rule.** A state that must stand out (copied, selected, announced) swaps to the inverted tone; it is never lifted with a shadow or painted blue.

## Typography

**Display Font:** system UI sans (`system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`)
**Body Font:** the same stack
**Label/Mono Font:** `ui-monospace, "SF Mono", Menlo, Consolas, monospace`, only for inline technical tokens inside prose (file names, commands)

**Character:** one native sans used by decision, so the codes read like the platform's own numerals; character comes from heavy weights, wide tracking on figures and tight tracking on headings, not from a second face. Tabular figures are on for the whole body.

### Hierarchy
- **Code Hero** (650, `clamp(2.75rem, 13vw, 4.5rem)`, line-height 1, tracking 0.06em): the code on an opened account. On phones it grows to `clamp(2.75rem, 16.5vw, 5.5rem)`; eight-digit codes use `clamp(2.25rem, 12.5vw, 4.5rem)` so they still fit one line.
- **Display** (800, `clamp(2rem, 6vw, 2.75rem)`, line-height 1.08, tracking -0.03em, max 18ch): the welcome title only.
- **Code** (650, 1.75rem, 1.5rem below 40rem, line-height 1.1, tracking 0.05em): the code on each list tag, right-aligned, grouped `123 456` or `1234 5678`.
- **Headline** (700, 1.5rem, line-height 1.2, tracking -0.015em, balanced wrap): page titles.
- **Title** (700, 1.0625rem): plate headings.
- **Brand** (800, 1.125rem, tracking 0.02em): the lowercase `otpx` mark in the bar.
- **Body** (400, 1rem, line-height 1.5): everything else; issuer lines take 700 for rank. Leads, notices and notes cap at 62ch.
- **Button** (650, 1rem): plain, primary and danger buttons. Quiet buttons drop to 500 and carry a blue underline instead.
- **Label** (650, 0.875rem): field labels, tabs, the copied mark, danger and advanced summaries.
- **Small** (400, 0.875rem): hints, meta lines, next code, sync state, chips, back link.
- **Eyelet Numeral** (650, 0.6875rem; 0.875rem in the big tag): seconds left, inside the countdown ring.
- **Secret** (650, 1.125rem, tracking 0.06em, line-height 1.7, word-spacing 0.2em): recovery codes; the raw account secret uses 1.0625rem at 0.08em. Both wrap anywhere.

### Named Rules
**The Figures Carry It Rule.** Codes, counters and secrets are always tabular, grouped, and tracked wide (0.05em to 0.08em). Never set a code in a proportional figure or without its group space.

**The Weight Not Size Rule.** A list tag shows two sizes at rest, body and code; issuer versus account is told by weight (700 against 400) and ink, not by a third size.

## Layout

A single centered column capped at 46rem (`measure`), padded 1rem at the sides, 1.25rem at the top and 5rem plus the safe-area inset at the bottom, leaving room under the last tag for the toast. The bar spans the viewport but its content aligns to the same 46rem column through computed side padding, and it is sticky.

Rhythm runs on a quarter-rem scale: 0.5rem between tags on the board, 0.75rem to 1rem inside forms and blocks, 1.25rem between plates and inside them, 1.5rem inside the big account tag. Interactive targets are 2.75rem (44px) on the page and 2.5rem in the bar. Paired fields use an auto-fit grid of 10rem minimum columns.

Start, unlock and empty screens push content down with `clamp()` top padding (up to 4rem, 5rem for unlock) rather than vertical centering. The unlock card is a single plate capped at 24rem.

Below 40rem the bar wraps: brand and icon buttons on the first row, search full width on the second; the sync label collapses to its icon; the list code steps down to 1.5rem; account actions become a two-column grid; the opened account's title is visually hidden so the code owns the screen. Below 22rem the add tabs drop their labels and keep icons. On pointer devices the next code appears on hover or focus; on touch devices it stays hidden on the list and is shown on the opened account.

**The One Column Rule.** Every screen is one column under 46rem; extra width goes to the ground, never to a second column or a sidebar.

## Elevation & Depth

The system is flat. Surfaces are told apart by tone (white cards on an off-white ground, zinc cards on near-black) and a 1px edge, not by shadow. Movement and depth appear only twice:

### Shadow Vocabulary
- **Copy lift** (`translate: 0 -2px`, no shadow): the copied card rises one hairline as it inverts. Removed under reduced motion.
- **Floating toast** (`box-shadow: 0 6px 20px oklch(0% 0 0 / 0.22)`): the toast is the only element that floats over content.

### Named Rules
**The Flat Card Rule.** Cards, buttons, fields and tabs never cast shadows. If something needs to stand out, invert it or give it the accent; do not lift it.

## Shapes

Two corner radii carry the whole system: cards at 12px (list cards, plates, choices, tab strip, QR card, camera frame) and controls at 9px (buttons, fields, notices, tabs, toast, search, bar buttons). The focus ring uses 4px, inline code 5px, chips are full pills. The only circles are the countdown ring and the icon badge on start choices.

Every card has a 1px edge in `edge`, every field one in `field-edge`; ground-level notices and chips use `rule`. A list card is split into two hit areas by a 1px vertical divider: the wide copy area and a 2.75rem chevron to open the account, with the card's corners shared between them.

The countdown ring is drawn, not imaged: a hard-stop conic fill from the blue line to the edge tone around a smaller centre, so the remaining time is literally the length of the arc.

## Components

### Bar
Zinc-900 shell in both schemes, sticky, 3.75rem minimum height, content aligned to the 46rem column and to the top safe-area inset.
- **Brand:** lowercase `otpx`, 800 weight, links home.
- **Search:** zinc-800 well with no visible edge at rest, 2.5rem tall, magnifier icon inset left; on focus the edge turns blue with no offset. `/` focuses it from anywhere; Enter copies the first match.
- **Buttons:** 2.5rem icon buttons, text visually hidden; hover and current page fill with zinc-800. Sync state shows an icon plus a small label (muted, full white when never synced or failing); its icon spins at 1.1s per turn while busy.
- **Focus:** blue-400 ring inside the bar.

### Card (list item)
The core unit: a card with the countdown ring, name and code.
- **Layout:** three-column grid inside the copy area: ring, name (issuer 700 over account in muted ink, both ellipsised), code right-aligned with the next code or the copied mark stacked beneath. A 2.75rem chevron cell on the right opens the account.
- **Hover:** the `hover` fill on whichever cell is hovered; the next code fades in over 160ms.
- **Copied (the inverted card):** the whole card swaps to `invert` with `on-invert` text, lifts 2px, hides the next code and shows a check with "Copied" until the clipboard clears; only one card is inverted at a time. Transitions run 220ms on the house ease.
- **HOTP:** code masked as `••• •••`, ring solid blue (a counter, not a timer).

### Countdown ring
2.5rem (3.5rem on the big card): a blue arc around a 1.875rem centre (2.625rem big) that holds the seconds left. The arc depletes continuously (updated every 250ms from fractional seconds), turns red with a red numeral at five seconds or fewer, and is solid blue for counters and the still ring on unlock. The numeral means the countdown is never told by colour alone.

### Big Card (one account)
The card at full size, 1.5rem padding: ring and name on the first row, the hero code across the full width, the next code always visible beneath. Below it, the actions row (Copy as primary, QR, Share, Edit), then meta in small muted text, chips, note, a quiet "show the secret" button, and a collapsed danger zone.

### Plates
Cards with 12px corners, 1px edge, 1.25rem padding. Forms, the unlock card, recovery codes, sync remotes and settings blocks all sit in plates. Remotes nested in a plate lose their own box and become rows divided by a bottom edge. The collapsible "add a remote" plate uses a 3.25rem summary row.

### Buttons
- **Shape:** gently rounded controls (9px), 2.75rem tall, 1rem side padding, icon and label with a 0.5rem gap, 650 weight.
- **Plain (default):** surface fill, edge border, ink; hover takes the `hover` fill.
- **Primary:** blue-600 fill and border, white text; hover blue-700. One per action group.
- **Danger:** transparent, red outline and text; hover fills with the red wash. Lives inside a collapsed danger zone.
- **Quiet:** no fill or border, 500 weight, underlined in blue at 0.2em offset; hover thickens the underline to 2px.
- **Disabled:** 55% opacity, not-allowed cursor; busy buttons show the progress cursor. Background transitions run 160ms.

### Fields
- **Style:** `field` fill (white in light, near-black in dark), 1px `field-edge` border, 9px corners, 2.75rem minimum height, 0.5rem by 0.75rem padding, ink text, blue caret, muted placeholder.
- **Label and hint:** label above in 650 small; hint below in small muted ink, wired with `aria-describedby`.
- **Focus:** border takes the focus colour and the 2px ring sits flush (offset 0).
- **Disabled:** 60% opacity. Checkboxes are 1.25rem with a blue accent inside a 2.75rem row.

### Notices
A one-line statement of what happens to the data, or what went wrong, set beside its action. 9px corners, 0.75rem by 0.875rem padding, small text, max 62ch.
- **Proof:** outline only (rule on the ground, edge in a plate), muted text, no icon.
- **Warn:** amber wash with amber border and an alert icon.
- **Error:** red wash with red border, alert icon, announced as an alert.

### Tabs
The add screen's four-way switch (Scan, Image, Paste, Manual): a surface strip with 12px corners and 0.25rem padding holding four equal 2.5rem tabs. Inactive tabs are muted ink at label weight; the selected tab inverts. Labels shrink to 0.8125rem below 40rem and disappear below 22rem, leaving icons.

### Toast
A short status line, bottom centre, above the safe area, max `min(92vw, 34rem)`. Inverted tone, 9px corners; errors use red-600 with white text. It rises 1rem and fades in (260ms translate, 200ms opacity), stays 3.6s (7s for errors), and is a polite live region.

### Choices (start screen)
Card rows with 12px corners: a 2.5rem round blue-wash badge holding the icon in blue ink, a title with a small muted description, and a trailing chevron. Hover takes the `hover` fill.

### Chips
Pills with a rule outline, small muted text, 0.125rem by 0.625rem padding. Used for an account's tags only.

### Icons
One hand-drawn stroke family on a 24-unit grid: 1.75 stroke, round caps and joins, no fill, `currentColor`, 1.25rem by default (1rem in back links and the copied mark, 1.125rem in notices). The star is the only filled icon (amber, outlined in dark amber). Icons are decorative unless they carry the only label, in which case they get an accessible name.

## Do's and Don'ts

### Do:
- **Do** put every account on its own card in the single ordered column, with the countdown ring at left and the code right-aligned.
- **Do** invert a copied card, lift it 2px, and keep it inverted until the clipboard clears; invert only one card at a time.
- **Do** keep the ring numeral visible whenever the arc changes colour, so time left is never conveyed by colour alone.
- **Do** group codes (`123 456`, `1234 5678`) and set them in tabular figures at 650 weight with 0.05em or wider tracking.
- **Do** state where a secret goes in a notice next to the action that sends, stores or shows it.
- **Do** use the house ease (`cubic-bezier(0.16, 1, 0.3, 1)`) at 160 to 260ms for state changes, and collapse all motion and the copy lift under reduced motion.
- **Do** keep 2.75rem targets on the page and 2.5rem in the bar.
- **Do** use the focus token of the scheme: blue-600 on light, blue-400 on dark and in the bar.

### Don't:
- **Don't** use blue as a card fill, a heading colour, or a second primary button in the same action group.
- **Don't** use red for anything that is not destructive, failing, or expiring, nor amber for anything but warnings and the star.
- **Don't** add gradients or shadows to cards, buttons, fields or tabs; the ring's hard-stop conic arc and the toast's float are the only exceptions.
- **Don't** add a third type size or a second typeface to a list card; rank issuer and account by weight and ink.
- **Don't** add a second column, a sidebar, or widen the content beyond 46rem.
- **Don't** introduce filled or multi-weight icons beside the stroke set; the amber star is the only filled glyph.
