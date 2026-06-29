"use client";

// ───────────────────────────────────────────────────────────────────────────
// The ONE shared modal / drawer primitive. Every overlay uses this so
// positioning can never break:
//   • a single `fixed inset-0` CONTAINER owns viewport anchoring;
//   • the panel inside is flex-placed (right drawer / centre modal), never
//     `fixed`, so decorative `position: relative` classes can't displace it;
//   • the scrim is `absolute inset-0` (never `fixed`).
// Responsive: width is `min(vw, px)` so it fits narrow screens and is capped on
// wide ones. Consumers provide a `shrink-0` header + a `flex-1 min-h-0
// overflow-auto` body so content scrolls inside the viewport.
// ───────────────────────────────────────────────────────────────────────────

import { useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { cn } from "@/lib/cn";

export type OverlayPlacement = "right" | "center";

export interface OverlayProps {
  open: boolean;
  onClose: () => void;
  placement?: OverlayPlacement;
  /** Stacking level (a nested drawer passes a higher value). Default 50. */
  z?: number;
  /** Tailwind max-width class for the panel (defaults are responsive). */
  widthClass?: string;
  label?: string;
  /** Scrim-click / Escape closes (default true). */
  dismissable?: boolean;
  children: React.ReactNode;
}

export function Overlay({
  open,
  onClose,
  placement = "right",
  z = 50,
  widthClass,
  label,
  dismissable = true,
  children,
}: OverlayProps) {
  useEffect(() => {
    if (!open || !dismissable) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, dismissable, onClose]);

  const isCenter = placement === "center";
  const panelWidth = widthClass ?? (isCenter ? "max-w-[min(94vw,880px)]" : "max-w-[min(94vw,560px)]");

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          key="overlay"
          className={cn("fixed inset-0 flex", isCenter ? "items-center justify-center p-4 sm:p-6" : "justify-end")}
          style={{ zIndex: z }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
        >
          <motion.div
            aria-hidden
            className="absolute inset-0 bg-black/70 backdrop-blur-[2px]"
            onClick={dismissable ? onClose : undefined}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          />
          <motion.div
            className={cn(
              "glass-modal relative flex w-full flex-col border-border shadow-[0_24px_70px_-24px_rgba(0,0,0,0.9)]",
              panelWidth,
              isCenter ? "max-h-[90vh] overflow-hidden border" : "h-full border-l",
            )}
            initial={isCenter ? { opacity: 0, scale: 0.97, y: 12 } : { x: "100%" }}
            animate={isCenter ? { opacity: 1, scale: 1, y: 0 } : { x: 0 }}
            exit={isCenter ? { opacity: 0, scale: 0.98, y: 8 } : { x: "100%" }}
            transition={{ type: "spring", stiffness: 320, damping: 36 }}
            role="dialog"
            aria-modal="true"
            aria-label={label}
          >
            {children}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export default Overlay;
