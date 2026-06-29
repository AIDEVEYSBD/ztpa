// Barrel for the UI primitive library. Import everything from "@/components/ui"
// (or "./ui" / "../ui"). `cn` is re-exported here so component files have one
// import surface for class merging + primitives.

export { cn } from "@/lib/cn";

export { Panel } from "./Panel";
export type { PanelProps } from "./Panel";

export { Chip } from "./Chip";
export type { ChipProps, ChipVariant } from "./Chip";

export { Overlay } from "./Overlay";
export type { OverlayProps, OverlayPlacement } from "./Overlay";

export { ScrollArea } from "./ScrollArea";
export type { ScrollAreaProps } from "./ScrollArea";

export { Stat, StatPill } from "./Stat";
export type { StatTone, StatPillProps } from "./Stat";

export { SeverityPill, ToolBadge, Tag } from "./Badges";
export { SEV } from "./severity";

export { Skeleton, SkeletonText, SkeletonRows, SkeletonPanel } from "./Skeleton";

export { Spinner, SectionLabel, Eyebrow, SpectrumLine, Brand, EmptyState } from "./Feedback";
