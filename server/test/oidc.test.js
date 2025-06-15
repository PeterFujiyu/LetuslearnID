process.env.DB_FILE=':memory:';
import request from 'supertest';
import assert from 'assert';
import { promisify } from 'util';
import { app, initDb, initOIDC, db } from '../index.js';
import jwt from 'jsonwebtoken';
import { loginToSso } from '../sso.js';
const get = promisify(db.get.bind(db));

describe('OIDC config and login', () => {
  before(async () => {
    await initDb();
    await initOIDC();
  });

  it('creates default client', async () => {
    const row = await get('SELECT client_id FROM oidc_clients');
    assert.ok(row);
  });

  it('exposes OIDC configuration', async () => {
    const res = await request(app).get('/.well-known/openid-configuration');
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.issuer);
  });

  it('has client fields', async () => {
    const row = await get('SELECT * FROM oidc_clients');
    assert.match(row.client_id, /^[0-9a-f-]{36}$/i);
    assert.match(row.client_secret, /^[0-9a-f]{32}$/i);
  });

  it('generates sso token for user', async () => {
    const token = await loginToSso(db, 'tester');
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    assert.strictEqual(payload.sub, 'tester');
    assert.strictEqual(payload.org, 'Letuslearn');
    assert.strictEqual(payload.app, 'LetuslearnID');
  });

});


