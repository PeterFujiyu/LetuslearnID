const { chromium } = require('playwright');
const assert = require('assert');
process.env.DB_FILE = ':memory:';
const { app, initDb, db } = require('../index');

let server, browser, page;

before(async function() {
  this.timeout(20000);
  await initDb();
  server = app.listen(3000);
  browser = await chromium.launch();
  page = await browser.newPage();
});

after(async function() {
  await browser.close();
  await new Promise(r => server.close(r));
});

describe('Browser flows', function() {
  this.timeout(20000);
  it('can register, login and fetch profile', async function() {
    await page.goto('http://localhost:3000');
    const username = 'bob';
    const password = 'pass123';
    // register
    let res = await page.evaluate(async ({u, p}) => {
      const r = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p })
      });
      return { status: r.status, body: await r.json() };
    }, {u: username, p: password});
    assert.strictEqual(res.status, 201);
    // login
    res = await page.evaluate(async ({u, p}) => {
      const r = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p })
      });
      const body = await r.json();
      if (r.ok) localStorage.setItem('token', body.token);
      return { status: r.status, body };
    }, {u: username, p: password});
    assert.strictEqual(res.status, 200);
    const token = await page.evaluate(() => localStorage.getItem('token'));
    assert.ok(token);
    // profile
    const profile = await page.evaluate(async (t) => {
      const r = await fetch('/profile', {
        headers: { 'Authorization': 'Bearer ' + t }
      });
      return { status: r.status, body: await r.json() };
    }, token);
    assert.strictEqual(profile.status, 200);
    assert.strictEqual(profile.body.username, username);
  });
});
