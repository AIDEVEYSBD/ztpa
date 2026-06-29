import type { Config } from "tailwindcss";

/**
 * Design tokens map to the CSS custom properties declared in `globals.css`
 * (theme-aware: light under `:root`/`[data-theme="light"]`, dark under
 * `[data-theme="dark"]`). The CSS vars are the single source of truth; this
 * file only exposes them to Tailwind's utility generator.
 *
 * Doctrine (shared with the reference design system): enterprise / "confident"
 * — squared (the radius scale is zeroed so every `rounded-*` is sharp), flat,
 * hairline borders, electric-yellow accent, Arial type. Depth comes from the
 * glass/aurora/glow primitives in `globals.css`, not from rounding.
 */
const config: Config = {
  darkMode: ["selector", '[data-theme="dark"]'],
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // ── canvas / surfaces ───────────────────────────────────────────────
        bg: "var(--bg)",
        canvas: "var(--bg)",
        surface: "var(--surface)",
        surface2: "var(--surface-2)",
        surfaceHover: "var(--surface-hover)",
        sunk: "var(--surface-sunk)",
        elevated: "var(--elevated)",
        border: "var(--border)",
        borderStrong: "var(--border-strong)",
        hair: "var(--hair)",
        // ── type ────────────────────────────────────────────────────────────
        text: "var(--text)",
        text2: "var(--text-2)",
        text3: "var(--text-3)",
        // ── brand accent ────────────────────────────────────────────────────
        accent: {
          DEFAULT: "var(--accent)",
          2: "var(--accent-2)",
          ink: "var(--accent-ink)",
          soft: "var(--accent-soft)",
          press: "var(--accent-press)",
          // Foreground-safe accent: bright yellow on the dark canvas, a readable
          // gold on light surfaces. Use for accent TEXT/ICONS; `accent` (bright
          // yellow) is for fills/borders/swatches, not text on light backgrounds.
          fg: "var(--accent-fg)",
        },
        // ── state semantics ─────────────────────────────────────────────────
        ok: { DEFAULT: "var(--ok)", bg: "var(--ok-bg)", line: "var(--ok-line)" },
        info: { DEFAULT: "var(--info)", bg: "var(--info-bg)", line: "var(--info-line)" },
        sev: {
          critical: "var(--sev-critical)", "critical-bg": "var(--sev-critical-bg)", "critical-line": "var(--sev-critical-line)",
          high: "var(--sev-high)", "high-bg": "var(--sev-high-bg)", "high-line": "var(--sev-high-line)",
          medium: "var(--sev-medium)", "medium-bg": "var(--sev-medium-bg)", "medium-line": "var(--sev-medium-line)",
          low: "var(--sev-low)", "low-bg": "var(--sev-low-bg)", "low-line": "var(--sev-low-line)",
        },
        // ── aliases kept so older markup re-skins automatically ──────────────
        panel: "var(--surface)",
        ink: "var(--text)",
        muted: "var(--text-2)",
        faint: "var(--text-3)",
        line: "var(--border)",
      },
      fontFamily: {
        sans: ["Arial", '"Helvetica Neue"', "Helvetica", '"Liberation Sans"', "sans-serif"],
        mono: ['"SFMono-Regular"', '"SF Mono"', "Menlo", "Consolas", '"Liberation Mono"', "monospace"],
      },
      borderRadius: {
        none: "0", sm: "0", DEFAULT: "0", md: "0", lg: "0", xl: "0", "2xl": "0", "3xl": "0", full: "9999px",
      },
      screens: {
        // Extend coverage up to large desktops so the console fills the canvas.
        "3xl": "1920px",
        "4xl": "2560px",
      },
      boxShadow: {
        panel: "0 18px 50px -30px rgba(0,0,0,0.55)",
        glow: "0 0 0 1px var(--accent-glow), 0 18px 60px -22px rgba(255,230,0,0.35)",
        pop: "0 12px 32px -12px rgba(0,0,0,0.45)",
      },
    },
  },
  plugins: [],
};
export default config;
