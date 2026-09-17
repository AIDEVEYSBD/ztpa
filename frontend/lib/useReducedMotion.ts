"use client";

import { useEffect, useState } from "react";

/**
 * True when the viewer has asked their OS for reduced motion.
 *
 * Lived privately in ExplorerPanel until the packet walk needed the same
 * answer. Two copies of a media-query hook is how one of them quietly stops
 * being honoured, and this one gates animation that a reader may be unable to
 * follow, so it is shared rather than duplicated.
 *
 * Starts FALSE and corrects after mount. That is the safe direction for a
 * preference that only ever REMOVES motion: a component that reads false during
 * SSR renders its animated form and settles to the static one, where the
 * opposite would flash motion at someone who asked for none.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => setReduced(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, []);
  return reduced;
}
