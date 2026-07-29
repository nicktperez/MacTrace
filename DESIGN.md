# MacTrace Design System

## Direction

An after-hours incident desk: neutral near-black surfaces, restrained crimson for selection
and critical attention, and cool cyan for live system state. Product information is dense but
never theatrical.

## Color

All authored colors use OKLCH.

```css
--bg: oklch(0.105 0 0);
--surface: oklch(0.145 0 0);
--surface-raised: oklch(0.185 0.006 10);
--ink: oklch(0.94 0 0);
--muted: oklch(0.68 0.006 10);
--primary: oklch(0.58 0.20 10.4);
--accent: oklch(0.76 0.13 205);
```

Severity colors include text labels and icons so color is never the only signal.

## Typography

Use the macOS system sans stack for interface copy and the system monospace stack for event
IDs, times, addresses, and command metadata. The scale is fixed and compact.

## Layout

A 224px desktop rail and fluid work area collapse into a horizontally scrollable top
navigation below 820px. Tables become stacked records below 680px. Panels use 12px radii at
most and borders without decorative shadows.

## Components

Buttons, inputs, status pills, data rows, timeline entries, charts, and drawers share an 8px
control radius. Focus is a high-contrast cyan outline. Motion is limited to live-state changes
and panel transitions at 180–220ms, with a reduced-motion fallback.

