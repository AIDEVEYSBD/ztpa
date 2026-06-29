import { OctagonAlert, TriangleAlert, CircleAlert, Circle } from "lucide-react";
import type { Band } from "@/lib/types";

/** Shared severity metadata — icon, chip classes, and the CSS colour var.
 *  Severity is always colour + icon + label (per the design language). */
export const SEV: Record<Band, { Icon: typeof Circle; cls: string; varName: string }> = {
  critical: { Icon: OctagonAlert, cls: "bg-sev-critical-bg text-sev-critical border-sev-critical-line", varName: "--sev-critical" },
  high: { Icon: TriangleAlert, cls: "bg-sev-high-bg text-sev-high border-sev-high-line", varName: "--sev-high" },
  medium: { Icon: CircleAlert, cls: "bg-sev-medium-bg text-sev-medium border-sev-medium-line", varName: "--sev-medium" },
  low: { Icon: Circle, cls: "bg-sev-low-bg text-sev-low border-sev-low-line", varName: "--sev-low" },
};
