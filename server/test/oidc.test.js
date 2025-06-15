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

  it('returns sso token on login', async () => {
    const reg = await request(app).post('/register').send({ username:'oidc', email:'o@e.c', password:'pw' });
    const row = await get('SELECT id, code FROM pending_codes WHERE id=?', reg.body.id);
    await request(app).post('/register/verify').send({ id: reg.body.id, code: row.code });
    const res = await request(app).post('/login').send({ username:'oidc', password:'pw' });
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.sso);
    const api = await request(app)
      .get('/api/auth/sso')
      .set('Authorization', 'Bearer ' + res.body.token)
      .query({ method: 'sso_get_token' });
    assert.strictEqual(api.status, 200);
    assert.ok(api.body.token);
  });

});
