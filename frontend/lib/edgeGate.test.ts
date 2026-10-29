import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { backendIdToken, gate, resetIdTokenCache } from "./edgeGate";

const req = (path: string, headers: Record<string, string> = {}) =>
  new NextRequest(new URL(path, "https://app.example.test"), { headers });
const VIEWER = { id: "sub-1", role: "viewer", email: "v@example.test" };
/** Headers the middleware forwards to the backend (Next encodes them on the response). */
const forwarded = (r: Response, name: string) => r.headers.get(`x-middleware-request-${name}`);

afterEach(() => { resetIdTokenCache(); vi.restoreAllMocks(); });

describe("edge lock", () => {
  it("answers 404 without this edge's id, and serves with it", async () => {
    const env = { NPR_EDGE_ID: "fd-123" };
    expect((await gate(req("/frr"), VIEWER, env)).status).toBe(404);
    expect((await gate(req("/frr", { "x-azure-fdid": "other" }), VIEWER, env)).status).toBe(404);
    expect((await gate(req("/frr", { "x-azure-fdid": "fd-123" }), VIEWER, env)).status).toBe(200);
  });
  it("locks public paths too", async () => {
    expect((await gate(req("/login"), null, { NPR_EDGE_ID: "fd-123" })).status).toBe(404);
  });
});

describe("session gate", () => {
  it("sends a visitor without a session to sign in, keeping where they were going", async () => {
    const r = await gate(req("/frr/exports?x=1"), null, {});
    expect(r.status).toBe(307);
    const to = new URL(r.headers.get("location")!);
    expect(to.pathname).toBe("/login");
    expect(to.searchParams.get("callbackUrl")).toBe("/frr/exports?x=1");
  });
  it("fails closed on a session without a role", async () => {
    const r = await gate(req("/api/exports"), { id: "sub-2", role: null }, {});
    expect(new URL(r.headers.get("location")!).pathname).toBe("/no-access");
    expect((await gate(req("/no-access"), { id: "sub-2", role: null }, {})).status).toBe(200);
  });
  it("passes public paths through untouched", async () => {
    const r = await gate(req("/login", { "x-npr-role": "admin" }), null, {});
    expect(r.status).toBe(200);
    expect(forwarded(r, "x-npr-role")).toBeNull();
  });
});

describe("actor headers", () => {
  it("drops every client-supplied x-npr-* header, the proxy secret included", async () => {
    const r = await gate(req("/api/exports", {
      "x-npr-role": "admin", "x-npr-proxy-secret": "forged", "x-npr-anything": "1",
    }), VIEWER, { NPR_PROXY_SECRET: " real-secret \n" });
    expect(forwarded(r, "x-npr-role")).toBe("viewer");
    expect(forwarded(r, "x-npr-email")).toBe("v@example.test");
    expect(forwarded(r, "x-npr-sub")).toBe("sub-1");
    expect(forwarded(r, "x-npr-proxy-secret")).toBe("real-secret");          // trimmed like the backend
    expect(forwarded(r, "x-npr-anything")).toBeNull();
  });
});

describe("API credential (Cloud Run invoker IAM)", () => {
  it("attaches an ID token to API calls only", async () => {
    const mint = vi.fn(async () => "tok");
    const env = { NPR_BACKEND_AUDIENCE: "https://api.example.test" };
    const api = await gate(req("/api/exports"), VIEWER, env, mint);
    expect(forwarded(api, "x-serverless-authorization")).toBe("Bearer tok");
    expect(mint).toHaveBeenCalledWith("https://api.example.test");
    const page = await gate(req("/frr"), VIEWER, env, mint);
    expect(forwarded(page, "x-serverless-authorization")).toBeNull();
  });
  it("fails closed with a 503 that says why when no token can be had", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const r = await gate(req("/api/exports"), VIEWER, { NPR_BACKEND_AUDIENCE: "https://api" },
                         async () => { throw new Error("metadata down"); });
    expect(r.status).toBe(503);
    expect((await r.json()).error).toBe("backend credential unavailable");
  });
  it("caches the token until five minutes before it expires", async () => {
    const jwt = (exp: number) => `h.${btoa(JSON.stringify({ exp })).replace(/=+$/, "")}.s`;
    const now = Date.now() / 1000;
    const f = vi.fn(async () => new Response(jwt(now + 3600)));
    expect(await backendIdToken("aud", f as unknown as typeof fetch)).toBe(jwt(now + 3600));
    await backendIdToken("aud", f as unknown as typeof fetch);
    expect(f).toHaveBeenCalledTimes(1);
    await backendIdToken("other-aud", f as unknown as typeof fetch);         // another audience: new token
    expect(f).toHaveBeenCalledTimes(2);
    resetIdTokenCache();
    const g = vi.fn(async () => new Response(jwt(now + 200)));               // inside the 5-minute margin
    await backendIdToken("aud", g as unknown as typeof fetch);
    await backendIdToken("aud", g as unknown as typeof fetch);
    expect(g).toHaveBeenCalledTimes(2);
  });
  it("refuses a metadata server error", async () => {
    const f = vi.fn(async () => new Response("no", { status: 404 }));
    await expect(backendIdToken("aud", f as unknown as typeof fetch)).rejects.toThrow("404");
  });
});
