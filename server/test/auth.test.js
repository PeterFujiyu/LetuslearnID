process.env.DB_FILE = ':memory:';
import request from 'supertest';
import assert from 'assert';
import jwt from 'jsonwebtoken';
import { promisify } from 'util';
import { authenticator } from 'otplib';
import { app, initDb, db } from '../index.js';

before(async () => {
  await initDb();
});


describe('POST /register', () => {
  it('creates a new user', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'alice', email:'a@b.c', password: 'secret' });
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.id);
    const row = await promisify(db.get.bind(db))('SELECT code FROM pending_codes WHERE id=?', res.body.id);
    const vr = await request(app).post('/register/verify').send({ id: res.body.id, code: row.code });
    assert.strictEqual(vr.status, 201);
  });

  it('rejects duplicate usernames', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'alice', email:'c@d.e', password: 'secret' });
    assert.strictEqual(res.status, 409);
  });
});

describe('POST /login', () => {
  it('returns a token with valid credentials and rememberDays', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'alice', password: 'secret', rememberDays: 2 });
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.token);
    const decoded = jwt.decode(res.body.token);
    assert.strictEqual(Math.round((decoded.exp - decoded.iat) / 86400), 2);
    global.token = res.body.token;
  });

  it('rejects invalid credentials', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'alice', password: 'wrong' });
    assert.strictEqual(res.status, 401);
  });
});

describe('GET /profile', () => {
  it('requires authentication', async () => {
    const res = await request(app).get('/profile');
    assert.strictEqual(res.status, 401);
  });

  it('returns profile data with token', async () => {
    const res = await request(app)
      .get('/profile')
      .set('Authorization', `Bearer ${global.token}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.username, 'alice');
  });
});

describe('POST /change-password', () => {
  it('changes password for authenticated user', async () => {
    const res = await request(app)
      .post('/change-password')
      .set('Authorization', `Bearer ${global.token}`)
      .send({ oldPassword: 'secret', newPassword: 'newpass' });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.message, 'Password changed');
  });

  it('logs in with new password', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'alice', password: 'newpass' });
    assert.strictEqual(res.status, 200);
  });

  it('enables totp and requires verification', async () => {
    let r = await request(app)
      .post('/totp/setup')
      .set('Authorization', 'Bearer ' + global.token);
    assert.strictEqual(r.status, 200);
    const { secret, codes } = r.body;
    global.secret = secret;
    global.codes = codes;
    const otp = authenticator.generate(secret);
    r = await request(app)
      .post('/login')
      .send({ username: 'alice', password: 'newpass' });
    assert.strictEqual(r.body.tfa, true);
    const verify = await request(app)
      .post('/totp/verify')
      .send({ token: r.body.temp, code: otp });
    assert.ok(verify.body.token);
    global.token = verify.body.token;
  });
});


describe('Session persistence', () => {
  it('saves session settings and performs auto login', async () => {
    let r = await request(app).post('/login').send({ username: 'alice', password: 'newpass' , rememberDays:2 });
    const otp = authenticator.generate(global.secret);
    const vr = await request(app).post('/totp/verify').send({ token: r.body.temp, code: otp });
    const token = vr.body.token;
    const fp = 'testfp';
    await request(app)
      .post('/session')
      .set('Authorization', 'Bearer ' + token)
      .send({ fingerprint: fp, days: 2 })
      .expect(200);
    const res = await request(app).get('/auto-login').query({ fp });
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.token);
  });
});

describe('POST /logout', () => {
  it('deletes session and rejects old token', async () => {
    let r = await request(app).post('/login').send({ username: 'alice', password: 'newpass', rememberDays:2 });
    const otp = authenticator.generate(global.secret);
    const vr = await request(app).post('/totp/verify').send({ token: r.body.temp, code: otp });
    const token = vr.body.token;
    const fp = 'logoutfp';
    await request(app)
      .post('/session')
      .set('Authorization', 'Bearer ' + token)
      .send({ fingerprint: fp, days: 2 })
      .expect(200);
    await request(app)
      .post('/logout')
      .set('Authorization', 'Bearer ' + token)
      .send({ fingerprint: fp })
      .expect(200);
    const auto = await request(app).get('/auto-login').query({ fp });
    assert.strictEqual(auto.status, 404);
    const res = await request(app)
      .get('/profile')
      .set('Authorization', 'Bearer ' + token);
    assert.strictEqual(res.status, 403);
  });
});

describe('TOTP and backup codes', () => {
  it('allows login using a backup code once', async () => {
    let r = await request(app).post('/login').send({ username: 'alice', password: 'newpass' });
    assert.strictEqual(r.body.tfa, true);
    const verify = await request(app)
      .post('/totp/verify')
      .send({ token: r.body.temp, code: global.codes[0] });
    assert.ok(verify.body.token);
    global.token = verify.body.token;

    r = await request(app).post('/login').send({ username: 'alice', password: 'newpass' });
    const repeat = await request(app)
      .post('/totp/verify')
      .send({ token: r.body.temp, code: global.codes[0] });
    assert.strictEqual(repeat.status, 401);
  });

  it('regenerates backup codes with totp code', async () => {
    const otp = authenticator.generate(global.secret);
    const prev = await request(app)
      .post('/totp/regenerate?preview=1')
      .set('Authorization', 'Bearer ' + global.token)
      .send({ code: otp });
    assert.strictEqual(prev.status, 200);
    assert.ok(Array.isArray(prev.body.codes));
    const otp2 = authenticator.generate(global.secret);
    const res = await request(app)
      .post('/totp/regenerate')
      .set('Authorization', 'Bearer ' + global.token)
      .send({ code: otp2 });
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.codes));
    assert.strictEqual(res.body.codes.length, 12);
    assert.notStrictEqual(res.body.codes[0], global.codes[0]);
    global.codes = res.body.codes;
  });

  it('disables totp using backup code', async () => {
    const res = await request(app)
      .post('/totp/disable')
      .set('Authorization', 'Bearer ' + global.token)
      .send({ code: global.codes[0] });
    assert.strictEqual(res.status, 200);
    let r = await request(app).post('/login').send({ username: 'alice', password: 'newpass' });
    assert.ok(r.body.token);
    global.token = r.body.token;
  });
});

