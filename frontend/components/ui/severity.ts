import { OctagonAlert, TriangleAlert, CircleAlert, Circle } from "lucide-react";
import type { Band } from "@/lib/types";

/** Shared severity metadata — icon, chip classes, and the CSS colour var.
 *  Severity is always colour + icon + label (per the design language). */
export const SEV: Record<Band, { Icon: typeof Circle; cls: string; varName: string }> = {
  critical: { Icon: OctagonAlert, cls: "bg-err-bg text-err border-err-line", varName: "--t-err" },
  high: { Icon: TriangleAlert, cls: "bg-warn-bg text-warn border-warn-line", varName: "--t-warn" },
  medium: { Icon: CircleAlert, cls: "bg-run-bg text-run border-run-line", varName: "--t-run" },
  low: { Icon: Circle, cls: "bg-raise text-faint border-line", varName: "--t-fg-4" },
};
