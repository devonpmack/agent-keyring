import { PGlite } from '@electric-sql/pglite';
import pg from 'pg';

export interface Queryable {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>;
}

export interface Db extends Queryable {
  tx<T>(fn: (q: Queryable) => Promise<T>): Promise<T>;
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
}

// Postgres returns int8 as strings; every count in this codebase fits in int4,
// and timestamps come back as Date from both drivers.
export function createPgDb(connectionString: string): Db {
  const pool = new pg.Pool({ connectionString, max: 10 });
  return {
    async query<T>(sql: string, params: unknown[] = []) {
      const res = await pool.query(sql, params);
      return res.rows as T[];
    },
    async tx<T>(fn: (q: Queryable) => Promise<T>) {
      const client = await pool.connect();
      try {
        await client.query('begin');
        const result = await fn({
          async query<R>(sql: string, params: unknown[] = []) {
            const res = await client.query(sql, params);
            return res.rows as R[];
          },
        });
        await client.query('commit');
        return result;
      } catch (err) {
        await client.query('rollback');
        throw err;
      } finally {
        client.release();
      }
    },
    async exec(sql: string) {
      await pool.query(sql);
    },
    async close() {
      await pool.end();
    },
  };
}

// In-process Postgres (WASM): the test suite, and a no-Docker way to try the
// app (DATABASE_URL=pglite:.data/pglite). Not for production.
export function createPgliteDb(dataDir?: string): Db {
  const lite = new PGlite(dataDir);
  const wrap = (q: { query: PGlite['query'] }): Queryable => ({
    async query<T>(sql: string, params: unknown[] = []) {
      const res = await q.query<T>(sql, params);
      return res.rows;
    },
  });
  return {
    ...wrap(lite),
    tx: fn => lite.transaction(t => fn(wrap(t))),
    async exec(sql: string) {
      await lite.exec(sql);
    },
    async close() {
      await lite.close();
    },
  };
}

export function createDb(url: string): Db {
  if (url.startsWith('pglite:')) return createPgliteDb(url.slice('pglite:'.length) || undefined);
  return createPgDb(url);
}
