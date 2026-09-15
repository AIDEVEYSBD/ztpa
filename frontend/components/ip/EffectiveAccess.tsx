"use client";

/**
 * SECTION 4 — EFFECTIVE ACCESS, AND THE CAVEAT THAT IS PART OF THE CLAIM.
 *
 * The engine models the UNION OF ALLOW EDGES and does not implement deny
 * precedence (ENGINE.md §10.1). So `reachable_from_internet: false` means
 * exactly one thing — no allow path was found — and it does NOT mean the address
 * is provably blocked. Those two readings lead to opposite decisions, and the
 * difference between them is a sentence.
 *
 * Therefore the qualifier is rendered INSIDE the same block as the verdict, at
 * full size, never behind a hover, a tooltip, a "learn more" or a fold. It is
 * not possible to read the claim on this screen without also reading what it is
 * worth. Three consequences follow, and all three are deliberate:
 *
 *   • `false` is worded "no allow path found", never "not reachable".
 *   • `false` is NOT painted green. A green tile is itself a claim of safety,
 *     and the engine has not made one.
 *   • `null` is "not determined" — the third state, and never collapsed into
 *     false, which would turn "we did not compute this" into "you are fine".
 */

import { HelpCircle, ShieldAlert, ShieldQuestion } from "lucide-react";
import type { IpLookupResponse } from "@/lib/types";
import { Eyebrow, cn } from "@/components/ui";

/** Used when the payload carries no caveat of its own. The qualifier is not
 *  optional, so its absence upstream cannot be allowed to remove it here — and
 *  the substitution is labelled, so nobody mistakes our sentence for the
 *  engine's. */
const FALLBACK_CAVEAT =
  "The engine models the union of allow edges and does not implement deny precedence, so a negative result means no allow path was found — not that traffic is provably blocked.";

type Verdict = {
  headline: string;
  tone: string;
  icon: typeof ShieldAlert;
  iconTone: string;
  body: string;
};

function verdictFor(reachable: boolean | null): Verdict {
  if (reachable === true) {
    return {
      headline: "An allow path from the internet was found",
      tone: "border-sev-critical-line bg-sev-critical-bg",
      icon: ShieldAlert,
      iconTone: "text-sev-critical",
      body: "At least one chain of allow rules reaches this address from outside the estate. This is a positive finding and does not depend on the caveat below.",
    };
  }
  if (reachable === false) {
    return {
      // Deliberately not "not reachable", and deliberately not green.
      headline: "No allow path from the internet was found",
      tone: "border-border bg-sunk",
      icon: ShieldQuestion,
      iconTone: "text-text2",
      body: "The search over allow edges did not reach this address from outside the estate.",
    };
  }
  return {
    headline: "Not determined",
    tone: "border-sev-medium-line bg-sev-medium-bg",
    icon: HelpCircle,
    iconTone: "text-sev-medium",
    body: "The engine did not compute reachability for this address. That is not a negative result: nothing was found because nothing was looked for.",
  };
}

export function EffectiveAccess({ effective }: { effective: IpLookupResponse["effective"] }) {
  // A missing `effective` block is itself the null case — an absent answer is
  // never a "no".
  const reachable = effective?.reachable_from_internet ?? null;
  const v = verdictFor(reachable);
  const supplied = (effective?.caveat ?? "").trim();
  const caveat = supplied || FALLBACK_CAVEAT;
  const Icon = v.icon;

  return (
    <section className="space-y-3">
      <Eyebrow>Effective access</Eyebrow>

      <div className={cn("border", v.tone)}>
        <div className="flex items-start gap-3 p-3.5">
          <Icon size={18} className={cn("mt-0.5 shrink-0", v.iconTone)} />
          <div className="min-w-0 flex-1">
            <div className="label !text-[9.5px]">Reachable from the internet</div>
            <div className={cn("mt-1 text-[16px] font-bold leading-tight", v.iconTone)}>
              {reachable === null ? <span className="mono mr-1.5">—</span> : null}
              {v.headline}
            </div>
            <p className="mt-1 text-[12px] leading-relaxed text-text2">{v.body}</p>
          </div>
        </div>

        {/* The qualifier is part of the claim, so it lives in the same block and
            is always open. Do not make this collapsible. */}
        <div className="border-t border-dashed border-hair px-3.5 py-3">
          <div className="label mb-1 !text-[9.5px]">Read this with the claim</div>
          <p className="text-[12px] leading-relaxed text-text2">{caveat}</p>
          {!supplied && (
            <p className="mt-1.5 text-[11px] leading-relaxed text-text3">
              The payload carried no caveat, so this is the client&apos;s statement of the engine&apos;s
              documented limitation rather than the engine&apos;s own words.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
