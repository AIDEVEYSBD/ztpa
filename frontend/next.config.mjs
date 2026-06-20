/** @type {import('next').NextConfig} */
const BACKEND = process.env.BACKEND_URL || "http://127.0.0.1:8000";

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    // Proxy /api/* to FastAPI, EXCEPT /api/auth/* which Auth.js owns. (afterFiles
    // rewrites run before dynamic routes, so the [...nextauth] route needs the
    // negative-lookahead to not be swallowed by this proxy.)
    return [{ source: "/api/:path((?!auth).*)", destination: `${BACKEND}/api/:path` }];
  },
};

export default nextConfig;
