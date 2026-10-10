import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Db } from './index.js';

// Migrations are copied next to the compiled output by the build (see Dockerfile).
const dir = fileURLToPath(new URL('./migrations/', import.meta.url));

export async function migrate(db: Db): Promise<void> {
  await db.exec('create table if not exists schema_migrations (name text primary key, applied_at timestamptz not null)');
  const applied = new Set((await db.query<{ name: string }>('select name from schema_migrations')).map(r => r.name));
  const files = readdirSync(dir).filter(f => f.endsWith('.sql')).sort();
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = readFileSync(dir + file, 'utf8');
    await db.tx(async q => {
      for (const statement of splitStatements(sql)) await q.query(statement);
      await q.query('insert into schema_migrations (name, applied_at) values ($1, $2)', [file, new Date()]);
    });
  }
}

function splitStatements(sql: string): string[] {
  return sql
    .replace(/--.*$/gm, '')
    .split(';')
    .map(s => s.trim())
    .filter(Boolean);
}
