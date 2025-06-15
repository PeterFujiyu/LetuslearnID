import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import initOidcConfig from './oidcconfig.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbFile = process.env.DB_FILE || path.join(__dirname, 'users.db');
const db = new sqlite3.Database(dbFile);
const run = (q, p = []) => new Promise((res, rej) => db.run(q, p, err => err ? rej(err) : res()));
(async () => {
  await run('DROP TABLE IF EXISTS oidcauth');
  await run('DROP TABLE IF EXISTS oidc_clients');
  await run('DROP TABLE IF EXISTS oidc_keys');
  await initOidcConfig(db, true);
  db.close();
})();

