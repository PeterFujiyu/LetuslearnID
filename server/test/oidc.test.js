process.env.DB_FILE=':memory:';
import request from 'supertest';
import assert from 'assert';
import { promisify } from 'util';
import { app, initDb, db, initOidcConfig } from '../index.js';
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

});


