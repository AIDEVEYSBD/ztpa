// Email a password-reset link to an existing user (also live-tests Resend).
//   node scripts/send-reset.mjs <email>
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import crypto from "node:crypto";
import pg from "pg";
import { Resend } from "resend";

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
if (!email) { console.error("usage: node scripts/send-reset.mjs <email>"); process.exit(1); }
const conn = (env.DATABASE_URL || "").replace(/([?&])channel_binding=[^&]*/g, "$1").replace(/[?&]$/, "");
const APP = env.APP_URL || "http://localhost:3000";
const pool = new pg.Pool({ connectionString: conn, ssl: { rejectUnauthorized: false } });

const main = async () => {
  const { rows } = await pool.query("SELECT email FROM ztpa.app_users WHERE email=$1", [email]);
  if (!rows[0]) { console.error(`No such user: ${email} (create it first).`); await pool.end(); process.exit(1); }
  const token = crypto.randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + 30 * 60_000).toISOString();
  await pool.query("INSERT INTO ztpa.auth_tokens (token, email, purpose, expires) VALUES ($1,$2,'reset',$3)", [token, email, expires]);
  const url = `${APP}/reset?token=${token}`;

  if (env.RESEND_API_KEY) {
    try {
      const r = await new Resend(env.RESEND_API_KEY).emails.send({
        from: env.EMAIL_FROM || "ZeroTrust Advisor <onboarding@resend.dev>",
        to: email,
        subject: "Set your ZeroTrust Advisor password",
        html: `<p>Click to set your password (expires in 30 minutes):</p><p><a href="${url}">${url}</a></p>`,
      });
      if (r.error) console.log("Resend error:", JSON.stringify(r.error));
      else console.log("✓ Sent via Resend — message id:", r.data?.id);
    } catch (e) { console.log("Resend exception:", String(e)); }
  } else {
    console.log("(no RESEND_API_KEY set)");
  }
  console.log(`Reset link (30 min, works regardless of email):\n  ${url}`);
  await pool.end();
};

main().catch((e) => { console.error(e); process.exit(1); });
