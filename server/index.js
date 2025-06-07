const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { promisify } = require('util');

const app = express();
app.use(express.json());
const clientDir = path.join(__dirname, "..", "client");
app.use(express.static(clientDir));
app.use('/i18n', express.static(path.join(__dirname, '..', 'i18n')));
app.get('/', (req, res) => {
  res.sendFile(path.join(clientDir, 'index', 'index.html'));
});

const dbFile = process.env.DB_FILE || path.join(__dirname, 'users.db');
const db = new sqlite3.Database(dbFile);

// Initialize user table if it doesn't exist
const initDb = () => {
  const query = `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT,
    password_hash TEXT,
    totp_secret TEXT,
    backup_codes TEXT
  )`;
  const passkeyQuery = `CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    credential_id TEXT UNIQUE,
    public_key TEXT,
    counter INTEGER DEFAULT 0
  )`;
  const pendingQuery = `CREATE TABLE IF NOT EXISTS pending_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT,
    password_hash TEXT,
    code TEXT,
    action TEXT,
    created_at INTEGER
  )`;
  const sessionQuery = `CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    fingerprint TEXT,
    expires_at INTEGER
  )`;
  const alters = [
    'ALTER TABLE users ADD COLUMN email TEXT',
    'ALTER TABLE users ADD COLUMN totp_secret TEXT',
    'ALTER TABLE users ADD COLUMN backup_codes TEXT'
  ];
  return Promise.all([
    promisify(db.run.bind(db))(query),
    promisify(db.run.bind(db))(passkeyQuery),
    promisify(db.run.bind(db))(sessionQuery),
    promisify(db.run.bind(db))(pendingQuery),
    ...alters.map(a => promisify(db.run.bind(db))(a).catch(() => {}))
  ]);
};

require('./users')(app, db);

initDb().then(() => {
  if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  }
}).catch((err) => {
  console.error('Failed to initialize database', err);
});

module.exports = { app, initDb, db };
