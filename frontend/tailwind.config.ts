import type { Config } from "tailwindcss";

/** Tokens map to the design's CSS variables (see globals.css). Enterprise/flat:
 *  the radius scale is zeroed so every rounded-* becomes sharp, matching the design. */
const config: Config = {
  darkMode: ["selector", '[data-theme="dark"]'],
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)",
        surface: "var(--surface)",
        surface2: "var(--surface-2)",
        surfaceHover: "var(--surface-hover)",
        sunk: "var(--surface-sunk)",
        border: "var(--border)",
        borderStrong: "var(--border-strong)",
        hair: "var(--hair)",
        text: "var(--text)",
        text2: "var(--text-2)",
        text3: "var(--text-3)",
        accent: { DEFAULT: "var(--accent)", ink: "var(--accent-ink)", soft: "var(--accent-soft)", press: "var(--accent-press)" },
        ok: { DEFAULT: "var(--ok)", bg: "var(--ok-bg)", line: "var(--ok-line)" },
        sev: {
          critical: "var(--sev-critical)", "critical-bg": "var(--sev-critical-bg)", "critical-line": "var(--sev-critical-line)",
          high: "var(--sev-high)", "high-bg": "var(--sev-high-bg)", "high-line": "var(--sev-high-line)",
          medium: "var(--sev-medium)", "medium-bg": "var(--sev-medium-bg)", "medium-line": "var(--sev-medium-line)",
          low: "var(--sev-low)", "low-bg": "var(--sev-low-bg)", "low-line": "var(--sev-low-line)",
        },
        // aliases kept so older markup re-skins automatically
        panel: "var(--surface)",
        ink: "var(--text)",
        muted: "var(--text-2)",
        line: "var(--border)",
      },
      fontFamily: {
        sans: ['Arial', '"Helvetica Neue"', "Helvetica", '"Liberation Sans"', "sans-serif"],
        mono: ['"SFMono-Regular"', '"SF Mono"', "Menlo", "Consolas", '"Liberation Mono"', "monospace"],
      },
      borderRadius: {
        none: "0", sm: "0", DEFAULT: "0", md: "0", lg: "0", xl: "0", "2xl": "0", "3xl": "0", full: "9999px",
      },
    },
  },
  plugins: [],
};
export default config;
