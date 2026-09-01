import { Pool } from "pg";

/**
 * The auth pool. Everything that moves over this connection is a credential:
 * bcrypt password hashes, UNHASHED magic-link / reset / invite tokens, and the
 * role assignments the whole authorization model is built on.
 *
 * It therefore takes DATABASE_URL exactly as configured — no parameters are
 * stripped — and never disables certificate verification. The previous version
 * did both: it removed `channel_binding=require` from the URL and passed
 * `ssl: { rejectUnauthorized: false }`, which downgrades TLS to
 * encryption-without-identity, so anything that can answer for the database
 * host (DNS, a hostile network, a proxy) reads every token in transit and can
 * hand back rows of its choosing. Neon presents a publicly trusted certificate;
 * Node's default trust store verifies it with no extra configuration.
 */
let _pool: Pool | undefined;

function pool(): Pool {
  if (!_pool) {
    _pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      // node-postgres lets parameters parsed from the connection string win over
      // this object, so with the configured `sslmode=require` the URL already
      // selects a verified TLS connection. This is the floor for a URL that
      // carries no ssl parameters at all: still TLS, still verified.
      ssl: { rejectUnauthorized: true },
      max: 3,
    });
  }
  return _pool;
}

export async function q<T = any>(text: string, params: any[] = []): Promise<T[]> {
  const res = await pool().query(text, params);
  return res.rows as T[];
}
