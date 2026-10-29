import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, requestJson } from "./api";

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("a busy API (503 + Retry-After)", () => {
  it("is asked again for a read, after the wait it named", async () => {
    vi.useFakeTimers();
    const f = vi.fn()
      .mockResolvedValueOnce(json(503, { detail: "the service is busy" }, { "retry-after": "2" }))
      .mockResolvedValueOnce(json(200, { ok: true }));
    vi.stubGlobal("fetch", f);
    const p = requestJson<{ ok: boolean }>("/api/x");
    await vi.advanceTimersByTimeAsync(2000);
    await expect(p).resolves.toEqual({ ok: true });
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("gives up after two retries and reports the 503", async () => {
    vi.useFakeTimers();
    const f = vi.fn().mockImplementation(async () => json(503, { detail: "the service is busy" }, { "retry-after": "1" }));
    vi.stubGlobal("fetch", f);
    const p = requestJson("/api/x").catch((e) => e);
    await vi.advanceTimersByTimeAsync(5000);
    const err = await p;
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(503);
    expect(f).toHaveBeenCalledTimes(3);
  });

  it("never repeats a write", async () => {
    const f = vi.fn().mockResolvedValue(json(503, { detail: "busy" }, { "retry-after": "1" }));
    vi.stubGlobal("fetch", f);
    await expect(requestJson("/api/x", { method: "POST" })).rejects.toBeInstanceOf(ApiError);
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("does not wait on a 503 without Retry-After", async () => {
    const f = vi.fn().mockResolvedValue(json(503, { detail: "down" }));
    vi.stubGlobal("fetch", f);
    await expect(requestJson("/api/x")).rejects.toBeInstanceOf(ApiError);
    expect(f).toHaveBeenCalledTimes(1);
  });
});
