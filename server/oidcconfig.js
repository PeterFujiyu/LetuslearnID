import { promisify } from 'util';
import crypto from 'crypto';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import { generateKeyPair, exportJWK } from 'jose';

async function initOidcConfig(db, verbose = false) {
  const run = promisify(db.run.bind(db));
  const get = promisify(db.get.bind(db));
  await run(`CREATE TABLE IF NOT EXISTS oidc_auth (
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
  await run(`CREATE TABLE IF NOT EXISTS oidc_clients (
    id TEXT PRIMARY KEY,
    client_id TEXT,
    client_secret TEXT,
    redirect_uris TEXT,
    scopes TEXT DEFAULT 'openid profile email',
    grant_types TEXT DEFAULT 'authorization_code refresh_token',
    response_types TEXT DEFAULT 'code',
    token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS oidc_keys (
    kid TEXT PRIMARY KEY,
    kty TEXT,
    alg TEXT,
    use TEXT,
    key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  let created = false;
  let row = await get('SELECT * FROM oidc_auth LIMIT 1');
  let redirect;
  if (!row) {
    let domain;
    if (process.env.NODE_ENV === 'test' || process.env.DB_FILE === ':memory:') {
      domain = 'id.letuslearn.now';
      redirect = 'https://cloud.letuslearn.now/api/auth/sso_callback';
    } else {
      const rl = readline.createInterface({ input, output });
      domain = (await rl.question('请输入 LetuslearnID 部署域名（不含https://和末尾的/）: ')).trim();
      redirect = (await rl.question('请输入回调地址(如https://cloud.letuslearn.now/api/auth/sso_callback): ')).trim();
      rl.close();
    }

    const cfg = {
      client_id: crypto.randomUUID(),
      client_secret: crypto.randomBytes(16).toString('hex'),
      username_key: 'sub',
      org_name: 'Letuslearn',
      app_name: 'LetuslearnID',
      endpoint: `https://${domain}`,
      jwt_key: crypto.randomBytes(32).toString('hex'),
      extra_scope: 'profile email'
    };
    await run('INSERT INTO oidc_auth (client_id,client_secret,username_key,org_name,app_name,endpoint,jwt_key,extra_scope) VALUES (?,?,?,?,?,?,?,?)',
      Object.values(cfg));
    row = await get('SELECT * FROM oidc_auth LIMIT 1');
    created = true;
  } else {
    if (verbose) console.log('OIDC 配置:', row);
    redirect = 'https://cloud.letuslearn.now/api/auth/sso_callback';
  }

  const cCount = await get('SELECT COUNT(*) as c FROM oidc_clients');
  if (cCount.c === 0) {
    const id = crypto.randomUUID();
    const secret = crypto.randomBytes(16).toString('hex');
    const redirectUris = JSON.stringify([redirect]);
    await run('INSERT INTO oidc_clients (id,client_id,client_secret,redirect_uris) VALUES (?,?,?,?)',
      id, id, secret, redirectUris);
    created = true;
  }

  let keyRow = await get('SELECT kid,key FROM oidc_keys LIMIT 1');
  if (!keyRow) {
    const { privateKey } = await generateKeyPair('RS256', { extractable: true });
    const jwk = await exportJWK(privateKey);
    jwk.use = 'sig';
    jwk.alg = 'RS256';
    jwk.kid = crypto.randomUUID();
    await run('INSERT INTO oidc_keys (kid,kty,alg,use,key) VALUES (?,?,?,?,?)',
      jwk.kid, jwk.kty, jwk.alg, jwk.use, JSON.stringify(jwk));
    keyRow = { kid: jwk.kid, key: JSON.stringify(jwk) };
    created = true;
  }

  const client = await get('SELECT client_id,client_secret,redirect_uris FROM oidc_clients LIMIT 1');
  const cfg = { ...row, redirect_uris: JSON.parse(client.redirect_uris), kid: keyRow.kid };
  if (created) {
    console.log('OIDC 配置初次生成:', cfg);
  } else if (verbose) {
    console.log('OIDC 配置:', cfg);
  }
  return cfg;
}

export default initOidcConfig;
