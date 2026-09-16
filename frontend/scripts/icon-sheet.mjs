/**
 * Contact sheet for the network glyphs — render every icon at every size it is
 * actually used at, on both themes, so a change is judged by LOOKING.
 *
 *   node scripts/icon-sheet.mjs            -> /tmp/icon-sheet.html
 *
 * Why this exists: the set's own README states a 16px legibility floor, and
 * every identification surface in the app was rendering at 15 or 14. Nobody
 * noticed for the same reason nobody could have: there was no way to see the
 * glyphs side by side at their real sizes. Arguments about whether an L3 switch
 * reads differently from an L2 switch are unresolvable without this.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const SRC = "components/net/icons.tsx";
const out = ts.transpileModule(readFileSync(SRC, "utf8"), {
  compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
});
const mod = { exports: {} };
new Function("exports", "require", "module", "React", out.outputText)(
  mod.exports, (m) => (m === "react" ? React : require(m)), mod, React,
);
const { NET_ICONS } = mod.exports;

// The sizes the app actually renders at, plus a large one to judge the drawing.
const SIZES = [96, 24, 18, 16, 15, 13];
const names = Object.keys(NET_ICONS).sort();
const seen = new Set();
const unique = names.filter((n) => {
  const fn = NET_ICONS[n];
  if (seen.has(fn)) return false;
  seen.add(fn);
  return true;
});

const cell = (name, size) =>
  `<td style="text-align:center;padding:6px 10px">${
    renderToStaticMarkup(React.createElement(NET_ICONS[name], { size }))
  }</td>`;

const rows = unique.map((n) =>
  `<tr><th style="text-align:left;font:11px ui-monospace,monospace;font-weight:400;padding-right:14px;white-space:nowrap">${n}</th>${
    SIZES.map((s) => cell(n, s)).join("")
  }</tr>`).join("\n");

const table = (theme) => `
<section data-theme="${theme}" style="padding:22px;background:${theme === "dark" ? "#0B0B0F" : "#F1F1F5"};
  color:${theme === "dark" ? "#F7F7F8" : "#1A1A24"}">
  <h2 style="font:600 13px ui-sans-serif;margin:0 0 14px;letter-spacing:.04em;text-transform:uppercase">${theme}</h2>
  <table style="border-collapse:collapse">
    <tr><th></th>${SIZES.map((s) => `<th style="font:10px ui-monospace;font-weight:400;opacity:.6;padding-bottom:6px">${s}px</th>`).join("")}</tr>
    ${rows}
  </table>
</section>`;

writeFileSync("/tmp/icon-sheet.html", `<!doctype html><meta charset="utf-8">
<body style="margin:0;font-family:ui-sans-serif,system-ui">
<div style="display:grid;grid-template-columns:1fr 1fr">${table("dark")}${table("light")}</div>
</body>`);
console.log(`icon sheet: ${unique.length} glyphs x ${SIZES.length} sizes -> /tmp/icon-sheet.html`);
