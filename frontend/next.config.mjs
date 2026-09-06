/** @type {import('next').NextConfig} */
const BACKEND = process.env.BACKEND_URL || "http://127.0.0.1:8000";

const nextConfig = {
  reactStrictMode: true,
  // Container build: emit .next/standalone — the traced server plus only the
  // node_modules it actually reaches. Shipped with .next/static and public/.
  //
  // BACKEND_URL IS NOT A RUNTIME VARIABLE IN A PRODUCTION BUILD. `rewrites()`
  // below runs during `next build`, and the resolved destination string is
  // serialised into .next/routes-manifest.json. The production server reads that
  // manifest and never calls this function again (next/dist/server/lib/
  // router-utils/filesystem.js: when `!opts.dev` it JSON.parses routes-manifest
  // and uses routesManifest.rewrites). `output: "standalone"` did not cause this
  // — it is true of `next start` too — but it does matter here, because the
  // backend's Container Apps FQDN is not known until after the backend deploys,
  // so a baked value would force an image rebuild per environment.
  // The Dockerfile works around it: it builds with BACKEND_URL set to the
  // sentinel http://npr-backend.invalid and rewrites that string in
  // routes-manifest.json at container start from the real $BACKEND_URL.
  // The proper fix is to replace this rewrite with a catch-all Route Handler
  // (app/api/[...path]/route.ts) that reads process.env.BACKEND_URL per request
  // — that file is outside this workstream's ownership.
  output: "standalone",
  async rewrites() {
    // Proxy /api/* to FastAPI, EXCEPT /api/auth/* which Auth.js owns. (afterFiles
    // rewrites run before dynamic routes, so the [...nextauth] route needs the
    // negative-lookahead to not be swallowed by this proxy.)
    return [{ source: "/api/:path((?!auth).*)", destination: `${BACKEND}/api/:path` }];
  },
};

export default nextConfig;
