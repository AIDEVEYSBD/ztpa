import { Pool } from "pg";

// node-postgres can fail on Neon's `channel_binding=require`; strip it (we still
// use sslmode=require + ssl below). Auth tables live in `public`.
function connectionString(): string {
  return (process.env.DATABASE_URL || "").replace(/([?&])channel_binding=[^&]*/g, "$1").replace(/[?&]$/, "");
}

let _pool: Pool | undefined;
function pool(): Pool {
  if (!_pool) {
    _pool = new Pool({ connectionString: connectionString(), ssl: { rejectUnauthorized: false }, max: 3 });
  }
  return _pool;
}

export async function q<T = any>(text: string, params: any[] = []): Promise<T[]> {
  const res = await pool().query(text, params);
  return res.rows as T[];
}
