---
name: otpx
description: 2FA codes from an encrypted vault you keep, shown as tags on a concierge's key board.
colors:
  # Light scheme (default). Source of truth: web/static/app.css :root
  baize: "oklch(34% 0.066 162)"
  baize-deep: "oklch(28.5% 0.06 162)"
  on-baize: "oklch(96.5% 0.015 95)"
  on-baize-2: "oklch(83% 0.035 145)"
  brass: "oklch(73% 0.125 82)"
  brass-soft: "oklch(94% 0.04 88)"
  brass-ink: "oklch(29% 0.05 75)"
  vermilion: "oklch(55% 0.19 32)"
  vermilion-soft: "oklch(95% 0.03 35)"
  vermilion-ink: "oklch(47% 0.18 32)"
  on-vermilion: "oklch(98% 0.01 35)"
  ground: "oklch(95.6% 0.009 95)"
  fg: "oklch(25% 0.026 165)"
  fg-2: "oklch(42% 0.022 165)"
  rule: "oklch(86.5% 0.013 95)"
  tag: "oklch(98.7% 0.012 92)"
  tag-edge: "oklch(85% 0.016 92)"
  tag-ink: "oklch(24% 0.026 165)"
  tag-ink-2: "oklch(43% 0.022 165)"
  field: "oklch(100% 0 0)"
  hole: "oklch(90% 0.01 95)"
  focus: "oklch(34% 0.066 162)"
  focus-bar: "oklch(73% 0.125 82)"
  # Dark scheme (prefers-color-scheme: dark). Tokens not listed keep their light value.
  baize-dark: "oklch(30% 0.058 162)"
  baize-deep-dark: "oklch(24.5% 0.05 162)"
  brass-soft-dark: "oklch(30% 0.05 85)"
  brass-ink-dark: "oklch(25% 0.05 75)"
  vermilion-dark: "oklch(64% 0.18 32)"
  vermilion-soft-dark: "oklch(28% 0.06 32)"
  vermilion-ink-dark: "oklch(72% 0.16 32)"
  ground-dark: "oklch(19.5% 0.026 165)"
  fg-dark: "oklch(92% 0.014 95)"
  fg-2-dark: "oklch(77% 0.025 140)"
  rule-dark: "oklch(32% 0.03 165)"
  tag-dark: "oklch(87% 0.018 92)"
  tag-edge-dark: "oklch(73% 0.022 92)"
  tag-ink-dark: "oklch(21% 0.026 165)"
  tag-ink-2-dark: "oklch(36% 0.022 165)"
  field-dark: "oklch(95% 0.012 92)"
  hole-dark: "oklch(16% 0.024 165)"
  focus-dark: "oklch(86% 0.09 85)"
  focus-plate-dark: "oklch(30% 0.058 162)"
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
    backgroundColor: "{colors.baize}"
    textColor: "{colors.on-baize}"
    height: "{spacing.bar}"
    padding: "0.625rem 1rem"
  bar-search:
    backgroundColor: "{colors.baize-deep}"
    textColor: "{colors.on-baize}"
    rounded: "{rounded.control}"
    height: "{spacing.control-bar}"
    padding: "0 0.875rem 0 2.5rem"
  bar-button:
    textColor: "{colors.on-baize}"
    rounded: "{rounded.control}"
    typography: "{typography.small}"
    size: "{spacing.control-bar}"
  bar-button-active:
    backgroundColor: "{colors.baize-deep}"
    textColor: "{colors.on-baize}"
  tag:
    backgroundColor: "{colors.tag}"
    textColor: "{colors.tag-ink}"
    rounded: "{rounded.plate}"
    padding: "0.75rem 0.5rem 0.75rem 0.875rem"
  tag-copied:
    backgroundColor: "{colors.baize}"
    textColor: "{colors.on-baize}"
    rounded: "{rounded.plate}"
  tag-big:
    backgroundColor: "{colors.tag}"
    textColor: "{colors.tag-ink}"
    rounded: "{rounded.plate}"
    padding: "1.5rem"
  eyelet:
    backgroundColor: "{colors.brass}"
    rounded: "{rounded.round}"
    size: "2.5rem"
  eyelet-ending:
    backgroundColor: "{colors.vermilion}"
    rounded: "{rounded.round}"
    size: "2.5rem"
  eyelet-hole:
    backgroundColor: "{colors.hole}"
    textColor: "{colors.fg-2}"
    rounded: "{rounded.round}"
    typography: "{typography.eyelet-numeral}"
    size: "1.875rem"
  eyelet-big:
    backgroundColor: "{colors.brass}"
    rounded: "{rounded.round}"
    size: "3.5rem"
  plate:
    backgroundColor: "{colors.tag}"
    textColor: "{colors.tag-ink}"
    rounded: "{rounded.plate}"
    padding: "1.25rem"
  choice:
    backgroundColor: "{colors.tag}"
    textColor: "{colors.tag-ink}"
    rounded: "{rounded.plate}"
    padding: "0.875rem 1rem"
  button-plain:
    backgroundColor: "{colors.tag}"
    textColor: "{colors.tag-ink}"
    rounded: "{rounded.control}"
    typography: "{typography.button}"
    height: "{spacing.control}"
    padding: "0 1rem"
  button-primary:
    backgroundColor: "{colors.brass}"
    textColor: "{colors.brass-ink}"
    rounded: "{rounded.control}"
    typography: "{typography.button}"
    height: "{spacing.control}"
    padding: "0 1rem"
  button-danger:
    textColor: "{colors.vermilion}"
    rounded: "{rounded.control}"
    typography: "{typography.button}"
    height: "{spacing.control}"
    padding: "0 1rem"
  button-danger-hover:
    backgroundColor: "{colors.vermilion-soft}"
    textColor: "{colors.vermilion}"
  button-quiet:
    typography: "{typography.body}"
    height: "{spacing.control}"
    padding: "0 1rem"
  field:
    backgroundColor: "{colors.field}"
    textColor: "{colors.tag-ink}"
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
    backgroundColor: "{colors.brass-soft}"
    textColor: "{colors.fg}"
    rounded: "{rounded.control}"
    typography: "{typography.small}"
    padding: "0.75rem 0.875rem"
  notice-error:
    backgroundColor: "{colors.vermilion-soft}"
    textColor: "{colors.fg}"
    rounded: "{rounded.control}"
    typography: "{typography.small}"
    padding: "0.75rem 0.875rem"
  tabs:
    backgroundColor: "{colors.tag}"
    rounded: "{rounded.plate}"
    padding: "0.25rem"
  tab:
    textColor: "{colors.tag-ink-2}"
    rounded: "{rounded.control}"
    typography: "{typography.label}"
    height: "{spacing.control-bar}"
  tab-selected:
    backgroundColor: "{colors.baize}"
    textColor: "{colors.on-baize}"
    rounded: "{rounded.control}"
  toast:
    backgroundColor: "{colors.baize}"
    textColor: "{colors.on-baize}"
    rounded: "{rounded.control}"
    padding: "0.75rem 1rem"
  toast-error:
    backgroundColor: "{colors.vermilion}"
    textColor: "{colors.on-vermilion}"
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

**Creative North Star: "The Concierge's Key Board"**

otpx looks like the key cabinet behind a hotel desk. Each account hangs as an ivory tag in a single ordered column; its code is the number stamped on the tag, set large in heavy tabular figures. A deep baize-green shell (the top bar, the reversed plate of a copied tag, the selected tab, the toast) frames the board, and a warm stone ground sits behind the tags. The system is built for operating, not browsing: one column at most 46rem wide, search one keystroke away, a tap to copy, and nothing ornamental competing with the code.

Colour is flat and quarantined. Brass is the single accent and works as hardware: the countdown rim around each tag's punched eyelet, the primary action, the underline on links, the text selection. Vermilion appears only for destruction, errors, and the last five seconds of a code. Hierarchy comes from weight, case and reversal (ivory to green) rather than from extra sizes or colours. Light and dark schemes keep the same world: in dark the ground turns green-black, the ivory tags dim but stay light, and every control inside them keeps light-scheme behaviour.

The owner asked for sobriety, and the system answers with restraint, not greyness: no gradients of tone, no decorative imagery, no shadows used as styling. Every line that tells the user where a secret goes sits beside its action as a plain notice.

**Key Characteristics:**
- One centered column of ivory tags on stone (light) or green-black (dark), max 46rem.
- Baize green carries the shell and every reversed state; brass is the one accent; vermilion is reserved for danger and expiry.
- The eyelet countdown ring is the signature: a punched hole whose brass rim depletes with the code's remaining time.
- Codes in heavy tabular figures, grouped in threes or fours, with wide tracking.
- System UI sans throughout, by decision; rank by weight and reversal.
- Flat surfaces separated by a 1px edge; depth only where the object physically has it.

## Colors

A baize-and-ivory pair with brass hardware and a vermilion warning, all in OKLCH, each role re-tuned for the dark scheme rather than inverted.

### Primary
- **Baize Green** (`baize`): the shell. Top bar background, the reversed plate of a copied tag, the selected tab, the toast, the light-scheme focus ring and caret on fields, checkbox accent. In dark it deepens slightly (`baize-dark`) so the bar still reads above the green-black ground.
- **Deep Baize** (`baize-deep`): one step down inside the shell. The search field well, hover and current state of bar buttons, the copied tag's divider and hover, the camera frame.
- **Baize Paper** (`on-baize`): text and icons on baize, and the copied tag's code.
- **Baize Paper Muted** (`on-baize-2`): secondary text on baize: search placeholder and icon, sync state, the copied tag's account line and next code.

### Secondary
- **Brass** (`brass`): the single accent. The eyelet countdown rim, the primary button fill, the favourite star, link and quiet-button underlines, text selection, the body caret, the skip link, the scanner aim, and the focus ring on the bar (`focus-bar`).
- **Brass Wash** (`brass-soft`): background of warning notices (the QR "it holds the secret" line, risk notes). Dark: a deep olive wash (`brass-soft-dark`).
- **Brass Ink** (`brass-ink`): text on brass (primary buttons, selection, skip link) and the star's outline.

### Tertiary
- **Vermilion** (`vermilion`): destructive button outline and text, danger-zone summaries, error notice edge, error toast background, and the eyelet rim in a code's last five seconds. Brighter in dark (`vermilion-dark`) to hold contrast on green-black.
- **Vermilion Wash** (`vermilion-soft`): error notice background and danger-button hover.
- **Vermilion Ink** (`vermilion-ink`): the seconds numeral inside an ending eyelet. Dark keeps the light value inside ivory plates and uses `vermilion-ink-dark` inside the punched hole, where the dark ground shows through.
- **Error Toast Paper** (`on-vermilion`): text on the error toast.

### Neutral
- **Stone Ground** (`ground`): page background. Dark: green-black (`ground-dark`).
- **Ground Ink** (`fg`) and **Ground Ink Muted** (`fg-2`): text set directly on the ground: headings, leads, hints, meta lines, back links, the no-match line, proof notices.
- **Rule** (`rule`): hairline dividers on the ground: proof-notice border, chip outline, danger-zone top rule, scrollbar thumb.
- **Ivory Tag** (`tag`): every plate: list tags, the big account tag, form plates, the unlock tag, choices, remotes, the tab strip, plain buttons. Dark dims it to a parchment ivory (`tag-dark`) instead of turning it dark.
- **Tag Edge** (`tag-edge`): the 1px edge of every plate and field, the tag's chevron divider, the empty part of the eyelet rim.
- **Tag Ink** (`tag-ink`) and **Tag Ink Muted** (`tag-ink-2`): text on ivory. Issuer and code in ink; account, next code, hints and inactive tabs in muted ink.
- **Field White** (`field`): input, textarea and select fill; also the QR code's backing card. Dark: a warm off-white (`field-dark`).
- **Punched Hole** (`hole`): the eyelet's centre, where the ground shows through the tag. Dark: near-black (`hole-dark`).

### Focus
- **Focus Ring** (`focus`): 2px solid, 2px offset, on baize in light. On the bar it becomes brass (`focus-bar`). On the dark ground it becomes a pale brass (`focus-dark`); inside ivory plates in dark it returns to baize (`focus-plate-dark`) so the ring always contrasts with the surface it sits on.

### Named Rules
**The Hardware Rule.** Brass is hardware, not paint: rims, underlines, selection, and the primary action of a group. It never fills a plate, a heading, or a background region larger than a button.

**The Red Means Loss Rule.** Vermilion marks only what destroys, fails, or is about to expire. A vermilion element that is none of these is a bug.

**The Ivory Stays Light Rule.** In dark mode the tags dim but never invert; anything placed on an ivory plate keeps light-scheme controls, light-scheme ink and a dark focus ring.

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
- **Button** (650, 1rem): plain, primary and danger buttons. Quiet buttons drop to 500 and carry a brass underline instead.
- **Label** (650, 0.875rem): field labels, tabs, the copied mark, danger and advanced summaries.
- **Small** (400, 0.875rem): hints, meta lines, next code, sync state, chips, back link.
- **Eyelet Numeral** (650, 0.6875rem; 0.875rem in the big tag): seconds left, inside the punched hole.
- **Secret** (650, 1.125rem, tracking 0.06em, line-height 1.7, word-spacing 0.2em): recovery codes; the raw account secret uses 1.0625rem at 0.08em. Both wrap anywhere.

### Named Rules
**The Figures Carry It Rule.** Codes, counters and secrets are always tabular, grouped, and tracked wide (0.05em to 0.08em). Never set a code in a proportional figure or without its group space.

**The Weight Not Size Rule.** A list tag shows two sizes at rest, body and code; issuer versus account is told by weight (700 against 400) and ink, not by a third size.

## Layout

A single centered column capped at 46rem (`measure`), padded 1rem at the sides, 1.25rem at the top and 5rem plus the safe-area inset at the bottom, leaving room under the last tag for the toast. The bar spans the viewport but its content aligns to the same 46rem column through computed side padding, and it is sticky.

Rhythm runs on a quarter-rem scale: 0.5rem between tags on the board, 0.75rem to 1rem inside forms and blocks, 1.25rem between plates and inside them, 1.5rem inside the big account tag. Interactive targets are 2.75rem (44px) on the page and 2.5rem in the bar. Paired fields use an auto-fit grid of 10rem minimum columns.

Start, unlock and empty screens push content down with `clamp()` top padding (up to 4rem, 5rem for unlock) rather than vertical centering. The unlock tag is a single ivory plate capped at 24rem.

Below 40rem the bar wraps: brand and icon buttons on the first row, search full width on the second; the sync label collapses to its icon; the list code steps down to 1.5rem; account actions become a two-column grid; the opened account's title is visually hidden so the code owns the screen. Below 22rem the add tabs drop their labels and keep icons. On pointer devices the next code appears on hover or focus; on touch devices it stays hidden on the list and is shown on the opened account.

**The One Column Rule.** Every screen is one column under 46rem; extra width goes to the ground, never to a second column or a sidebar.

## Elevation & Depth

The system is flat. Surfaces are told apart by tone (ivory on stone, baize on everything) and a 1px edge, not by shadow. Depth appears only where the object has it physically, and only three times:

### Shadow Vocabulary
- **Punched hole** (`box-shadow: inset 0 1px 2px oklch(0% 0 0 / 0.28)`): the eyelet centre, so it reads as a hole through the tag.
- **Copy lift** (`translate: 0 -2px`, no shadow): the copied tag rises one hairline as it reverses to baize. Removed under reduced motion.
- **Floating toast** (`box-shadow: 0 6px 20px oklch(0% 0 0 / 0.22)`): the toast is the only element that floats over content.

### Named Rules
**The Flat Plate Rule.** Plates, buttons, fields and tabs never cast shadows. If something needs to stand out, reverse it to baize or give it brass; do not lift it.

## Shapes

Two corner radii carry the whole system: plates at 12px (tags, plates, choices, tab strip, QR card, camera frame) and controls at 9px (buttons, fields, notices, tabs, toast, search, bar buttons). The focus ring uses 4px, inline code 5px, chips are full pills. The only circle is the eyelet and the round brass badge on start choices.

Every plate and field has a 1px edge in `tag-edge`; ground-level notices and chips use `rule`. A list tag is split into two hit areas by a 1px vertical divider: the wide copy area and a 2.75rem chevron to open the account, with the plate's corners shared between them.

The eyelet is drawn, not imaged: a hard-stop conic fill from brass to tag edge around a smaller hole, so the remaining time is literally the length of the rim.

## Components

### Bar
Baize shell, sticky, 3.75rem minimum height, content aligned to the 46rem column and to the top safe-area inset.
- **Brand:** lowercase `otpx`, 800 weight, links home.
- **Search:** deep-baize well with no visible edge at rest, 2.5rem tall, magnifier icon inset left; on focus the edge turns brass with no offset. `/` focuses it from anywhere; Enter copies the first match.
- **Buttons:** 2.5rem icon buttons, text visually hidden; hover and current page fill with deep baize. Sync state shows an icon plus a small label (muted paper, full paper when never synced or failing); its icon spins at 1.1s per turn while busy.
- **Focus:** brass ring inside the bar.

### Tag (list item)
The core unit: an ivory plate with eyelet, name and code.
- **Layout:** three-column grid inside the copy area: eyelet, name (issuer 700 over account in muted ink, both ellipsised), code right-aligned with the next code or the copied mark stacked beneath. A 2.75rem chevron cell on the right opens the account.
- **Hover:** a brass-tinted ivory (`color-mix(in oklch, tag 92%, brass)`) on whichever cell is hovered; the next code fades in over 160ms.
- **Copied (the reversed plate):** the whole tag turns baize with paper text, lifts 2px, hides the next code and shows a check with "Copied" until the clipboard clears; only one tag is reversed at a time. Transitions run 220ms on the house ease.
- **HOTP:** code masked as `••• •••`, eyelet solid brass (a counter, not a timer).

### Eyelet
The countdown, 2.5rem (3.5rem on the big tag): a brass rim around a 1.875rem punched hole (2.625rem big) that holds the seconds left. The rim depletes continuously (updated every 250ms from fractional seconds), turns vermilion with a vermilion numeral at five seconds or fewer, and is solid brass for counters and the still eyelet on unlock. The numeral means the countdown is never told by colour alone.

### Big Tag (one account)
The tag at full size, 1.5rem padding: eyelet and name on the first row, the hero code across the full width, the next code always visible beneath. Below it, the actions row (Copy as primary, QR, Share, Edit), then meta in small muted text, chips, note, a quiet "show the secret" button, and a collapsed danger zone.

### Plates
Ivory, 12px corners, 1px tag-edge border, 1.25rem padding. Forms, the unlock tag, recovery codes, sync remotes and settings blocks all sit in plates. Inside a plate, headings use tag ink and paragraphs, hints and notices switch to tag-ink tones. Remotes nested in a plate lose their own box and become rows divided by a bottom edge. The collapsible "add a remote" plate uses a 3.25rem summary row.

### Buttons
- **Shape:** gently rounded controls (9px), 2.75rem tall, 1rem side padding, icon and label with a 0.5rem gap, 650 weight.
- **Plain (default):** ivory fill, tag-edge border, tag ink; hover mixes 12% brass into the ivory.
- **Primary:** brass fill and border, brass-ink text; hover mixes 14% brass ink into the brass. One per action group.
- **Danger:** transparent, vermilion outline and text; hover fills with vermilion wash. Lives inside a collapsed danger zone.
- **Quiet:** no fill or border, 500 weight, underlined in brass at 0.2em offset; hover thickens the underline to 2px.
- **Disabled:** 55% opacity, not-allowed cursor; busy buttons show the progress cursor. Background transitions run 160ms.

### Fields
- **Style:** white fill (warm off-white in dark), 1px tag-edge border, 9px corners, 2.75rem minimum height, 0.5rem by 0.75rem padding, tag ink text, baize caret, muted placeholder.
- **Label and hint:** label above in 650 small; hint below in small muted ink, wired with `aria-describedby`.
- **Focus:** border takes the focus colour and the 2px ring sits flush (offset 0).
- **Disabled:** 60% opacity. Checkboxes are 1.25rem with a baize accent inside a 2.75rem row.

### Notices
A one-line statement of what happens to the data, or what went wrong, set beside its action. 9px corners, 0.75rem by 0.875rem padding, small text, max 62ch.
- **Proof:** outline only (rule on the ground, tag edge in a plate), muted text, no icon.
- **Warn:** brass wash with brass border and an alert icon.
- **Error:** vermilion wash with vermilion border, alert icon, announced as an alert.
- **Dark, inside a plate:** warn and error take light washes (`oklch(93% 0.04 88)`, `oklch(92% 0.035 35)`) with tag ink, so they stay legible on the dimmed ivory.

### Tabs
The add screen's four-way switch (Scan, Image, Paste, Manual): an ivory strip with 12px corners and 0.25rem padding holding four equal 2.5rem tabs. Inactive tabs are muted ink at label weight; the selected tab reverses to baize with paper text. Labels shrink to 0.8125rem below 40rem and disappear below 22rem, leaving icons.

### Toast
A short status line, bottom centre, above the safe area, max `min(92vw, 34rem)`. Baize with paper text, 9px corners; errors use vermilion with paper text. It rises 1rem and fades in (260ms translate, 200ms opacity), stays 3.6s (7s for errors), and is a polite live region.

### Choices (start screen)
Ivory rows with 12px corners: a 2.5rem round brass badge holding the icon, a title with a small muted description, and a trailing chevron. Hover tints the ivory with brass.

### Chips
Pills with a rule outline, small muted text, 0.125rem by 0.625rem padding. Used for an account's tags only.

### Icons
One hand-drawn stroke family on a 24-unit grid: 1.75 stroke, round caps and joins, no fill, `currentColor`, 1.25rem by default (1rem in back links and the copied mark, 1.125rem in notices). The star is the only filled icon (brass, outlined in brass ink). Icons are decorative unless they carry the only label, in which case they get an accessible name.

## Do's and Don'ts

### Do:
- **Do** put every account on its own ivory tag in the single ordered column, with the eyelet at left and the code right-aligned.
- **Do** reverse a copied tag to baize, lift it 2px, and keep it reversed until the clipboard clears; reverse only one tag at a time.
- **Do** keep the eyelet numeral visible whenever the rim changes colour, so time left is never conveyed by colour alone.
- **Do** group codes (`123 456`, `1234 5678`) and set them in tabular figures at 650 weight with 0.05em or wider tracking.
- **Do** state where a secret goes in a notice next to the action that sends, stores or shows it.
- **Do** use the house ease (`cubic-bezier(0.16, 1, 0.3, 1)`) at 160 to 260ms for state changes, and collapse all motion and the copy lift under reduced motion.
- **Do** keep 2.75rem targets on the page and 2.5rem in the bar.
- **Do** switch the focus ring to the colour that contrasts with its surface: baize on light and on ivory, brass in the bar, pale brass on the dark ground.

### Don't:
- **Don't** use brass as a surface fill, a heading colour, or a second primary button in the same action group.
- **Don't** use vermilion for anything that is not destructive, failing, or expiring.
- **Don't** add tonal gradients or shadows to plates, buttons, fields or tabs; the eyelet's hard-stop conic rim and the toast's float are the only exceptions.
- **Don't** invert the ivory tags in dark mode or let dark-scheme controls render inside them.
- **Don't** add a third type size or a second typeface to a list tag; rank issuer and account by weight and ink.
- **Don't** add a second column, a sidebar, or widen the content beyond 46rem.
- **Don't** introduce filled or multi-weight icons beside the stroke set; the brass star is the only filled glyph.
