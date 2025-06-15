process.env.DB_FILE=':memory:';
import request from 'supertest';
import assert from 'assert';
import { promisify } from 'util';
import { app, initDb, db, initOidcConfig } from '../index.js';
import jwt from 'jsonwebtoken';
import { loginToSso } from '../sso.js';
const get = promisify(db.get.bind(db));

describe('OIDC config and login', () => {
  before(async () => {
    await initDb();
    await initOidcConfig(db, true);
  });

  it('creates oidcauth row', async () => {
    const row = await get('SELECT client_id FROM oidcauth');
    assert.ok(row);
  });

  it('exposes OIDC configuration', async () => {
    const res = await request(app).get('/oidc/.well-known/openid-configuration');
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.issuer);
  });

  it('has valid config fields', async () => {
    const row = await get('SELECT * FROM oidcauth');
    assert.match(row.client_id, /^[0-9a-f-]{36}$/i);
    assert.match(row.client_secret, /^[0-9a-f]{32}$/i);
    assert.match(row.jwt_key, /^[0-9a-f]{64}$/i);
    assert.strictEqual(row.username_key, 'sub');
    assert.ok(row.endpoint.startsWith('https://'));
  });

  it('generates sso token for user', async () => {
    const row = await get('SELECT * FROM oidcauth');
    const token = await loginToSso(db, 'tester');
    const payload = jwt.verify(token, row.jwt_key);
    assert.strictEqual(payload[row.username_key], 'tester');
    assert.strictEqual(payload.org, row.org_name);
    assert.strictEqual(payload.app, row.app_name);
  });

});


