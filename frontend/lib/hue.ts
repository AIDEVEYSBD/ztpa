export type Hue = "red" | "green" | "amber" | "violet" | "teal" | "indigo" | "blue" | "slate";

/**
 * A card header bar carries a translucent tint for its subject. The subject is
 * read from the title, so a card tints itself without the caller choosing a
 * colour. Order matters: the first pattern that matches wins.
 */
const RULES: ReadonlyArray<readonly [Hue, RegExp]> = [
  ["red", /guardrail|control|denial|kill|refusal|finding|breach|risk|threat|critical|violation|exposure/i],
  ["green", /spend|finops|budget|cost|billing|price|model|licence|license/i],
  ["amber", /approval|gate|sign|person|people|human|queue|pending|review/i],
  ["violet", /knowledge|source|corpus|retrieval|pipeline|document|admission|telemetry|artifact|output|report|evidence/i],
  ["teal", /identity|credential|key|vault|ingress|mcp|attached|audit|privilege|account|owner/i],
  ["indigo", /latency|observability|trace|routing|peer|roster|ledger|journal|change|history/i],
  ["blue", /activity|health|live|run|theatre|estate|lifecycle|workflow|agent|deploy|connected|configuration|tool|policy|rule|topology|inventory|address|connector/i],
];

export function hueFor(title: string | null | undefined): Hue {
  if (!title) return "teal";
  for (const [hue, pattern] of RULES) {
    if (pattern.test(title)) return hue;
  }
  return "teal";
}
