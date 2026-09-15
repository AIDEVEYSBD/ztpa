"use client";

/**
 * CSV export for the inventory table.
 *
 * WHAT THIS FILE IS CAREFUL ABOUT, and why each one matters for a file that
 * leaves the product and gets mailed to a client:
 *
 *   QUOTING. RFC 4180: a field containing a comma, a quote, a CR or an LF is
 *   wrapped in quotes and its own quotes are doubled. Anything less and one
 *   firewall rule with a comma in it silently shifts every column after it.
 *
 *   FORMULA INJECTION. A cell beginning `=`, `+`, `-`, `@`, or a leading tab /
 *   CR is executed by Excel and Sheets when the file is opened. Inventory cells
 *   carry attacker-influenced strings (hostnames, tags, rule refs), so every
 *   such cell is prefixed with an apostrophe — the standard defusing, and
 *   visible in the file rather than a silent rewrite.
 *
 *   THE UNKNOWN MARKER. An em-dash on screen means "no source reported this".
 *   It must not flatten to an empty cell in the export, because an empty cell
 *   in a spreadsheet reads as zero/none — the exact lie this product exists to
 *   avoid. Unknown exports as the literal token below.
 *
 *   A BOM. Excel on Windows reads a UTF-8 file without one as Latin-1 and
 *   mangles every non-ASCII character in a hostname. The BOM is three bytes and
 *   removes an entire class of "your export is corrupted" reports.
 */

/** What an unreported field exports as. Not "", which reads as none. */
export const CSV_UNKNOWN = "(not reported)";

const NEEDS_QUOTES = /[",\r\n]/;
const FORMULA_LEAD = /^[=+\-@\t\r]/;

/** One CSV field: defused, then quoted if it needs to be. */
export function csvCell(value: string | null | undefined): string {
  if (value === null || value === undefined || value === "") return "";
  let v = String(value).replace(/—/g, CSV_UNKNOWN);
  if (FORMULA_LEAD.test(v)) v = `'${v}`;
  return NEEDS_QUOTES.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

/** A whole sheet. CRLF line endings, because that is what RFC 4180 says and
 *  what the spreadsheet on the reviewer's laptop expects. */
export function toCsv(rows: (string | null | undefined)[][]): string {
  return rows.map((r) => r.map(csvCell).join(",")).join("\r\n");
}

/**
 * Hand the file to the browser.
 *
 * Returns false when the browser gave us no way to do it, so the caller can say
 * so instead of leaving a button that looks like it worked. An object URL is
 * revoked on the next tick — not immediately, which cancels the download in
 * Safari.
 */
export function downloadCsv(filename: string, csv: string): boolean {
  try {
    if (typeof window === "undefined" || typeof document === "undefined") return false;
    const blob = new Blob(["﻿", csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    return true;
  } catch {
    return false;
  }
}

/** `inventory-2026-09-15-1432.csv` — sortable, and distinguishable from the
 *  five other exports already in the reviewer's downloads folder. */
export function csvFilename(stem: string, snapshot?: string): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  const stamp = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
  const snap = snapshot ? `-${snapshot.replace(/^snap_/, "").slice(0, 8)}` : "";
  return `${stem}${snap}-${stamp}.csv`;
}
