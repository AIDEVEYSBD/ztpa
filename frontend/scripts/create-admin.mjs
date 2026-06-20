// Bootstrap the first admin (or promote an existing user).
//   node scripts/create-admin.mjs <email>        # prints a single-use sign-in link
//   ADMIN_PASSWORD=... node scripts/create-admin.mjs <email>   # sets a password instead
// Reads DATABASE_URL / APP_URL / ADMIN_EMAIL from the repo-root .env.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import crypto from "node:crypto";
import pg from "pg";
import bcrypt from "bcryptjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function loadEnv() {
  const env = {};
  try {
    for (const line of readFileSync(path.join(root, ".env"), "utf8").split("\n")) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (!m) continue;
      let v = m[2].trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      env[m[1]] = v;
    }
  } catch {}
  return env;
}

const env = { ...loadEnv(), ...process.env };
const email = (process.argv[2] || env.ADMIN_EMAIL || "").toLowerCase().trim();
if (!email) {
  console.error("usage: node scripts/create-admin.mjs <email>   (or set ADMIN_EMAIL in .env)");
  process.exit(1);
}
const conn = (env.DATABASE_URL || "").replace(/([?&])channel_binding=[^&]*/g, "$1").replace(/[?&]$/, "");
const APP = env.APP_URL || "http://localhost:3000";
const pool = new pg.Pool({ connectionString: conn, ssl: { rejectUnauthorized: false } });

const main = async () => {
  await pool.query(
    `INSERT INTO ztpa.app_users (email, name, role, status) VALUES ($1, $2, 'admin', 'invited')
     ON CONFLICT (email) DO UPDATE SET role = 'admin'`,
    [email, "Administrator"],
  );
  const pw = process.argv[3] || env.ADMIN_PASSWORD;  // node create-admin.mjs <email> <password>
  if (pw) {
    const hash = await bcrypt.hash(pw, 10);
    await pool.query("UPDATE ztpa.app_users SET password_hash=$1, status='active', email_verified=now() WHERE email=$2", [hash, email]);
    console.log(`\n✓ Admin ready: ${email}\n  Sign in at ${APP}/login with the ADMIN_PASSWORD you set.\n`);
  } else {
    const token = crypto.randomBytes(32).toString("base64url");
    const expires = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    await pool.query("INSERT INTO ztpa.auth_tokens (token, email, purpose, expires) VALUES ($1,$2,'invite',$3)", [token, email, expires]);
    console.log(`\n✓ Admin created: ${email} (role=admin)\n  Activate + sign in (single-use, 24h):\n    ${APP}/login/magic?token=${token}\n  Then set a password via "Forgot password?" if you want password login.\n`);
  }
  await pool.end();
};

main().catch((e) => { console.error(e); process.exit(1); });
