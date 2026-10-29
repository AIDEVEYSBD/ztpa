// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Checkbox } from "./Form";

let host: HTMLDivElement | null = null;
afterEach(() => { host?.remove(); host = null; });

function render(ui: React.ReactElement) {
  host = document.createElement("div");
  document.body.appendChild(host);
  act(() => { createRoot(host!).render(ui); });
  return host;
}

describe("Checkbox", () => {
  it("is named by its label, for screen readers and tests", () => {
    const el = render(<Checkbox checked={false} onChange={() => {}} label="Partly covered above (14)" />);
    const box = el.querySelector('[role="checkbox"]')!;
    const label = document.getElementById(box.getAttribute("aria-labelledby")!);
    expect(label?.textContent).toBe("Partly covered above (14)");
    expect(box.getAttribute("aria-checked")).toBe("false");
  });

  it("toggles from a click on its text, once", () => {
    const onChange = vi.fn();
    const el = render(<Checkbox checked={false} onChange={onChange} label="Flagged rules only" />);
    const text = [...el.querySelectorAll("span")].find((s) => s.textContent === "Flagged rules only")!;
    act(() => { text.click(); });
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(true);
    act(() => { (el.querySelector('[role="checkbox"]') as HTMLElement).click(); });
    expect(onChange).toHaveBeenCalledTimes(2);                       // the box itself: still one call per click
  });

  it("toggles from the keyboard and ignores everything when disabled", () => {
    const onChange = vi.fn();
    const el = render(<Checkbox checked onChange={onChange} label="x" />);
    const box = el.querySelector('[role="checkbox"]') as HTMLElement;
    act(() => { box.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true })); });
    expect(onChange).toHaveBeenCalledWith(false);
    const off = vi.fn();
    const el2 = render(<Checkbox checked={false} onChange={off} label="y" disabled />);
    const box2 = el2.querySelector('[role="checkbox"]') as HTMLElement;
    act(() => { box2.click(); box2.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })); });
    expect(off).not.toHaveBeenCalled();
    expect(box2.tabIndex).toBe(-1);
  });
});
