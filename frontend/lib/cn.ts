import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merge conditional class names with Tailwind conflict resolution.
 *
 * `clsx` flattens conditionals/arrays/objects; `twMerge` then resolves
 * conflicting Tailwind utilities so the *last* one wins (e.g. `p-2 p-4` → `p-4`,
 * `text-text2 text-accent` → `text-accent`). This is the single class-name
 * helper for the whole app — import it from here or re-exported via
 * `@/components/ui`.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export default cn;
