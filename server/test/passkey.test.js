process.env.DB_FILE = ':memory:';
const request = require('supertest');
const assert = require('assert');
const { promisify } = require('util');
const { app, initDb, db } = require('../index');

const run = promisify(db.run.bind(db));
const get = promisify(db.get.bind(db));

before(async () => {
  await initDb();
});


describe('Passkey endpoints', () => {
  let token;

  before(async () => {
    await request(app)
      .post('/register')
      .send({ username: 'pkuser', password: 'secret' });
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
});
