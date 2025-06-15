import sqlite3pkg from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import { promisify } from 'util';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbFile = process.env.DB_FILE || path.join(__dirname, '..', 'users.db');
const sqlite3 = sqlite3pkg.verbose();
export const db = new sqlite3.Database(dbFile);

export const run = promisify(db.run.bind(db));
export const get = promisify(db.get.bind(db));
export const all = promisify(db.all.bind(db));

export async function initDb() {
  const queries = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      password_hash TEXT,
      totp_secret TEXT,
      backup_codes TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS passkeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      credential_id TEXT UNIQUE,
      public_key TEXT,
      counter INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      fingerprint TEXT,
      expires_at INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE,
      parent_id INTEGER,
      permissions TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS user_groups (
      user_id INTEGER,
      group_id INTEGER,
      PRIMARY KEY (user_id, group_id)
    )`,
    `CREATE TABLE IF NOT EXISTS pending_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      email TEXT,
      password_hash TEXT,
      code TEXT,
      action TEXT,
      created_at INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS verifycode (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      ip TEXT,
      code TEXT,
      expires_at INTEGER,
      authorized INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS oidc_clients (
      id TEXT PRIMARY KEY,
      client_id TEXT,
      client_secret TEXT,
      redirect_uris TEXT,
      scopes TEXT DEFAULT 'openid profile email',
      grant_types TEXT DEFAULT 'authorization_code refresh_token',
      response_types TEXT DEFAULT 'code',
      token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS oidc_keys (
      kid TEXT PRIMARY KEY,
      kty TEXT,
      alg TEXT,
      use TEXT,
      key TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
  ];

  for (const q of queries) {
    await run(q).catch(() => {});
  }

  await run("INSERT OR IGNORE INTO groups (id,name) VALUES (1,'admin')");
  await run("INSERT OR IGNORE INTO groups (id,name) VALUES (2,'user')");

  const count = await get('SELECT COUNT(*) as c FROM oidc_clients');
  if (count.c === 0) {
    const id = crypto.randomUUID();
    const secret = crypto.randomBytes(16).toString('hex');
    const redirect = JSON.stringify(['http://localhost:5244/oidc/callback']);
    await run('INSERT INTO oidc_clients (id,client_id,client_secret,redirect_uris) VALUES (?,?,?,?)',
      id, id, secret, redirect);
  }
}

export function getAllClients() {
  return all('SELECT * FROM oidc_clients');
}

export function getUserByName(name) {
  return get('SELECT * FROM users WHERE username=?', name);
}
