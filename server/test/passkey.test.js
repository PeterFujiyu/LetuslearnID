process.env.DB_FILE = ':memory:';
import request from 'supertest';
import assert from 'assert';
import { promisify } from 'util';
import { app, initDb, db } from '../index.js';

const run = promisify(db.run.bind(db));
const get = promisify(db.get.bind(db));

before(async () => {
  await initDb();
});


describe('Passkey endpoints', () => {
  let token;

  before(async () => {
    const reg = await request(app)
      .post('/register')
      .send({ username: 'pkuser', email:'pk@ex.com', password: 'secret' });
    const row = await get('SELECT id, code FROM pending_codes WHERE id=?', reg.body.id);
    await request(app).post('/register/verify').send({ id: reg.body.id, code: row.code });
    const res = await request(app)
      .post('/login')
      .send({ username: 'pkuser', password: 'secret' });
    token = res.body.token;
  });

  it('provides registration options', async () => {
    const res = await request(app)
      .post('/passkey/options')
      .set('Authorization', 'Bearer ' + token);
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.challenge);
  });

  it('fails registration with invalid response', async () => {
    const res = await request(app)
      .post('/passkey/register')
      .set('Authorization', 'Bearer ' + token)
      .send({});
    assert.strictEqual(res.status, 400);
  });

  it('returns passkey list in profile', async () => {
    const uid = (await get('SELECT id FROM users WHERE username=?', 'pkuser')).id;
    await run("INSERT INTO passkeys (user_id, credential_id, public_key, counter) VALUES (?, 'xyz', 'k', 0)", uid);
    const res = await request(app)
      .get('/profile')
      .set('Authorization', 'Bearer ' + token);
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.passkeys.includes('xyz'));
  });

  it('removes existing passkey', async () => {
    const uid = (await get('SELECT id FROM users WHERE username=?', 'pkuser')).id;
    await run("INSERT INTO passkeys (user_id, credential_id, public_key, counter) VALUES (?, 'a', 'b', 0)", uid);
    const res = await request(app)
      .post('/passkey/remove')
      .send({ credId: 'a' })
      .set('Authorization', 'Bearer ' + token);
    assert.strictEqual(res.status, 200);
    const row = await get('SELECT COUNT(*) as c FROM passkeys WHERE credential_id="a"');
    assert.strictEqual(row.c, 0);
  });

  it('provides auth options and fails verification', async () => {
    const uid = (await get('SELECT id FROM users WHERE username=?', 'pkuser')).id;
    await run("INSERT INTO passkeys (user_id, credential_id, public_key, counter) VALUES (?, 'abc', 'bcd', 0)", uid);
    await request(app)
      .post('/session')
      .set('Authorization', 'Bearer ' + token)
      .send({ fingerprint: 'fp1', days: 1 })
      .expect(200);
    const opt = await request(app)
      .post('/passkey/auth-options')
      .send({ fingerprint: 'fp1' });
    assert.strictEqual(opt.status, 200);
    const res = await request(app)
      .post('/passkey/auth?fingerprint=fp1')
      .send({ rawId: 'abc', response: {}, type: 'public-key' });
    assert.strictEqual(res.status, 400);
  });

  it('auth options with token when no session', async () => {
    const uid = (await get('SELECT id FROM users WHERE username=?', 'pkuser')).id;
    await run("INSERT INTO passkeys (user_id, credential_id, public_key, counter) VALUES (?, ?, 'pc', 0)", uid, Buffer.from('tok').toString('base64url'));
    const opt = await request(app)
      .post('/passkey/auth-options')
      .set('Authorization', 'Bearer ' + token)
      .send({ fingerprint: 'fpt' });
    assert.strictEqual(opt.status, 200);
    assert.ok(opt.body.challenge);
    const rid = Buffer.from('tok').toString('base64');
    const res = await request(app)
      .post('/passkey/auth?fingerprint=fpt')
      .send({ rawId: rid, response: {}, type: 'public-key' });
    assert.strictEqual(res.status, 400);
  });

  it('auth options using username', async () => {
    const uid = (await get('SELECT id FROM users WHERE username=?', 'pkuser')).id;
    await run("INSERT INTO passkeys (user_id, credential_id, public_key, counter) VALUES (?, ?, 'k', 0)", uid, Buffer.from('u123').toString('base64url'));
    const opt = await request(app)
      .post('/passkey/auth-options')
      .send({ fingerprint: 'fpu', username: 'pkuser' });
    assert.strictEqual(opt.status, 200);
    assert.ok(opt.body.challenge);
    const res = await request(app)
      .post('/passkey/auth?fingerprint=fpu')
      .send({ rawId: Buffer.from('u123').toString('base64'), response: {}, type: 'public-key' });
    assert.strictEqual(res.status, 400);
  });
});
