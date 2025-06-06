process.env.DB_FILE = ':memory:';
const request = require('supertest');
const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app, initDb, db } = require('../index');

before(async () => {
  await initDb();
});

after(done => {
  db.close(done);
});

describe('POST /register', () => {
  it('creates a new user', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'alice', password: 'secret' });
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.message, 'User registered');
  });

  it('rejects duplicate usernames', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'alice', password: 'secret' });
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
});

describe('Session persistence', () => {
  it('saves session settings and performs auto login', async () => {
    const token = (await request(app).post('/login').send({ username: 'alice', password: 'newpass' , rememberDays:2 })).body.token;
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

