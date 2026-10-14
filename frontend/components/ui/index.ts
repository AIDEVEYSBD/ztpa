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

// ── design-system primitives ───────────────────────────────────────
export { Material, SurfaceGrain } from "./Material";

export { Button, IconButton } from "./Button";
export type { ButtonProps, IconButtonProps, ButtonSize, ButtonVariant, Tone } from "./Button";

export { Status, StatusTag, Dot, Kicker, Mono, Identifier, Meter } from "./Status";

export { Field, Input, Textarea, Select, SearchBox, Checkbox, Switch, Segmented, WindowPick, WINDOWS } from "./Form";
export type { InputProps, Window } from "./Form";

export { DrillModal, Dialog, Banner } from "./Modal";

export { Table, THead, Th, Td, Tr, EmptyRow } from "./Table";

export { KpiTile, KpiBand, Kpi, Fact, PageHeader, PageFrame } from "./Kpi";

export { hueFor } from "@/lib/hue";
export type { Hue } from "@/lib/hue";
