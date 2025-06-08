import { promisify } from 'util';
import crypto from 'crypto';

async function initOidcConfig(db, verbose = false) {
  const run = promisify(db.run.bind(db));
  const get = promisify(db.get.bind(db));
  await run(`CREATE TABLE IF NOT EXISTS oidcauth (
    id INTEGER PRIMARY KEY,
    client_id TEXT,
    client_secret TEXT,
    username_key TEXT,
    org_name TEXT,
    app_name TEXT,
    endpoint TEXT,
    jwt_key TEXT,
    extra_scope TEXT
  )`);
  const row = await get('SELECT * FROM oidcauth LIMIT 1');
  if (!row) {
    const cfg = {
      client_id: crypto.randomUUID(),
      client_secret: crypto.randomBytes(16).toString('hex'),
      username_key: 'sub',
      org_name: 'Letuslearn',
      app_name: 'LetuslearnID',
      endpoint: 'https://sso.example.com',
      jwt_key: 'PUBLICKEY',
      extra_scope: 'profile email'
    };
    console.log('OIDC 配置初次生成:', cfg);
    await run('INSERT INTO oidcauth (client_id,client_secret,username_key,org_name,app_name,endpoint,jwt_key,extra_scope) VALUES (?,?,?,?,?,?,?,?)',
      Object.values(cfg));
    return cfg;
  } else {
    if (verbose) console.log('OIDC 配置:', row);
    return row;
  }
}

export default initOidcConfig;
