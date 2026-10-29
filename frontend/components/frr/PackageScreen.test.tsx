// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api";

const frr = vi.hoisted(() => ({
  me: vi.fn(), exportById: vi.fn(), draftPackage: vi.fn(), startRun: vi.fn(),
}));
vi.mock("@/lib/frr", () => ({ frr }));

import { PackageScreen } from "./PackageScreen";

let host: HTMLDivElement | null = null;
afterEach(() => { host?.remove(); host = null; vi.clearAllMocks(); });

async function renderScreen(setLink: (p: unknown) => void) {
  host = document.createElement("div");
  document.body.appendChild(host);
  await act(async () => {
    createRoot(host!).render(<PackageScreen exportId="e1" link={{}} setLink={setLink} onGoToExports={() => {}} />);
  });
  return host;
}

const button = (el: HTMLElement, text: string) =>
  [...el.querySelectorAll("button")].find((b) => b.textContent?.includes(text)) as HTMLButtonElement;

describe("Draft without narratives", () => {
  it("drafts inline when the API can", async () => {
    frr.me.mockResolvedValue({ role: "analyst", can_upload: true });
    frr.exportById.mockResolvedValue({ filename: "small.json" });
    frr.draftPackage.mockResolvedValue({ package_id: "p1" });
    const setLink = vi.fn();
    const el = await renderScreen(setLink);
    await act(async () => { button(el, "Draft without narratives").click(); });
    expect(frr.draftPackage).toHaveBeenCalledWith("e1", false);
    expect(frr.startRun).not.toHaveBeenCalled();
    expect(setLink).toHaveBeenCalledWith({ packageId: "p1", runId: undefined });
  });

  it("falls back to a background run without narratives when the export is too large to draft inline", async () => {
    frr.me.mockResolvedValue({ role: "analyst", can_upload: true });
    frr.exportById.mockResolvedValue({ filename: "big.json" });
    frr.draftPackage.mockRejectedValue(new ApiError(413, "the export has 110,001 rules", "/api/exports/e1/change-package"));
    frr.startRun.mockResolvedValue({ run_id: "r1" });
    const setLink = vi.fn();
    const el = await renderScreen(setLink);
    await act(async () => { button(el, "Draft without narratives").click(); });
    expect(frr.startRun).toHaveBeenCalledWith("e1", { narrate: false });
    expect(setLink).toHaveBeenCalledWith({ runId: "r1" });
    expect(el.textContent).not.toContain("Could not");          // no error shown for the handled 413
  });

  it("shows the export's file name in the header", async () => {
    frr.me.mockResolvedValue({ role: "analyst", can_upload: true });
    frr.exportById.mockResolvedValue({ filename: "estate-2026-10.json" });
    const el = await renderScreen(vi.fn());
    expect(el.textContent).toContain("estate-2026-10.json");
  });
});
