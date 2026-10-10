import { createDb } from './index.js';
import { migrate } from './migrate.js';

const url = process.env.DATABASE_URL;
if (!url) throw new Error('DATABASE_URL is required');
const db = createDb(url);
await migrate(db);
await db.close();
console.log('migrations applied');
