import express from 'express';
import sqlite3pkg from 'sqlite3';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { promisify } from 'util';
import initOidcConfig from './oidcconfig.js';
import Provider from 'oidc-provider';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
const clientDir = path.join(__dirname, "..", "client");
app.use(express.static(clientDir));
app.use('/i18n', express.static(path.join(__dirname, '..', 'i18n')));
app.get('/', (req, res) => {
  res.sendFile(path.join(clientDir, 'index', 'index.html'));
});

const dbFile = process.env.DB_FILE || path.join(__dirname, 'users.db');
const sqlite3 = sqlite3pkg.verbose();
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
  const verifyQuery = `CREATE TABLE IF NOT EXISTS verifycode (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip TEXT,
    code TEXT,
    expires_at INTEGER,
    authorized INTEGER DEFAULT 0
  )`;
  const sessionQuery = `CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    fingerprint TEXT,
    expires_at INTEGER
  )`;
  const groupQuery = `CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    parent_id INTEGER,
    permissions TEXT
  )`;
  const ugQuery = `CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER,
    group_id INTEGER,
    PRIMARY KEY (user_id, group_id)
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
    promisify(db.run.bind(db))(groupQuery),
    promisify(db.run.bind(db))(ugQuery),
    promisify(db.run.bind(db))(pendingQuery),
    promisify(db.run.bind(db))(verifyQuery),
    ...alters.map(a => promisify(db.run.bind(db))(a).catch(() => {}))
  ]).then(async () => {
    await promisify(db.run.bind(db))("INSERT OR IGNORE INTO groups (id,name) VALUES (1,'admin')");
    await promisify(db.run.bind(db))("INSERT OR IGNORE INTO groups (id,name) VALUES (2,'user')");
  });
};

import userRoutes from './users.js';
import adminRoutes from './admin.js';
import { loginToSso } from './sso.js';
const userMod = userRoutes(app, db);
adminRoutes(app, db, userMod.authenticateToken);


app.use('/admin', async (req,res,next)=>{
  let token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if(!token && req.query.t) token = req.query.t;
  try{
    const user = await userMod.verifyToken(token);
    const row = await promisify(db.get.bind(db))("SELECT 1 FROM user_groups ug JOIN groups g ON ug.group_id=g.id WHERE ug.user_id=? AND g.name='admin'", user.id);
    if(!row) return res.status(403).send('Forbidden');
    express.static(path.join(clientDir,'admin'))(req,res,next);
  }catch(err){
    res.status(401).send('Unauthorized');
  }
});

let oidc;
initDb()
  .then(() => initOidcConfig(db))
  .then(cfg => {
    const clients = [{
      client_id: cfg.client_id,
      client_secret: cfg.client_secret,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      redirect_uris: [cfg.endpoint + '/oidc/callback'],
      scope: 'openid profile email'
    }];
    oidc = new Provider(cfg.endpoint, {
      clients,
      formats: { AccessToken: 'jwt' },
      features: { devInteractions: { enabled: false } },
      findAccount: async (ctx, id) => ({ accountId: id, claims: () => ({ sub: id }) }),
      jwks: {
        keys: [{
          kty: 'oct',
          k: Buffer.from(cfg.jwt_key, 'hex').toString('base64url'),
          kid: 'signing-key-1'
        }]
      }
    });
    app.use('/oidc', oidc.callback());
    if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
      const PORT = process.env.PORT || 3000;
      app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    }
  })
  .catch((err) => {
    console.error('Failed to initialize database', err);
  });

export { app, initDb, initOidcConfig, db, oidc };
