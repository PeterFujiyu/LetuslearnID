// server/test/e2e.test.js
import { chromium } from 'playwright';
import assert from 'assert';
process.env.DB_FILE = ':memory:';
import { app, initDb, db } from '../index.js';  // 确保 index.js 导出了 app、initDb
import { promisify } from 'util';
const get = promisify(db.get.bind(db));

let server, browser, page;

before(async function() {
  this.timeout(20000);
  // 初始化内存数据库
  await initDb();
  // 启动 Express 服务
  server = app.listen(3000);
  // 启动无头浏览器
  browser = await chromium.launch();
  page = await browser.newPage();
});

after(async function() {
  // 只有 browser 存在时才关闭，防止启动失败导致 undefined.close()
  if (browser) {
    await browser.close();
  }
  // 关闭 HTTP 服务
  if (server) {
    await new Promise(resolve => server.close(resolve));
  }
});

describe('Browser flows', function() {
  this.timeout(20000);

  it('can register, login and fetch profile', async function() {
    await page.goto('http://localhost:3000');

    const username = 'bob';
    const password = 'pass123';

    // 1. 注册
    let res = await page.evaluate(async ({ u, p }) => {
      const r = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, email: 'u@e.test', password: p })
      });
      return { status: r.status, body: await r.json() };
    }, { u: username, p: password });
    assert.strictEqual(res.status, 200);
    const id = res.body.id;
    const row = await get('SELECT code FROM pending_codes WHERE id=?', id);
    const vr = await page.evaluate(async ({ i, c }) => {
      const r = await fetch('/register/verify', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id:i, code:c }) });
      return { status:r.status };
    }, { i: id, c: row.code });
    assert.strictEqual(vr.status, 201);

    // 2. 登录
    res = await page.evaluate(async ({ u, p }) => {
      const r = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p, rememberDays: 2 })
      });
      const body = await r.json();
      if (r.ok) localStorage.setItem('token', body.token);
      return { status: r.status, body };
    }, { u: username, p: password });
    assert.strictEqual(res.status, 200);

    // 从 localStorage 中读取 token
    const token = await page.evaluate(() => localStorage.getItem('token'));
    assert.ok(token);

    // 3. 获取个人信息
    const profile = await page.evaluate(async t => {
      const r = await fetch('/profile', {
        headers: { 'Authorization': 'Bearer ' + t }
      });
      return { status: r.status, body: await r.json() };
    }, token);
    assert.strictEqual(profile.status, 200);
    assert.strictEqual(profile.body.username, username);
  });

  it('provides passkey options with token', async function() {
    const token = await page.evaluate(() => localStorage.getItem('token'));
    const res = await page.evaluate(async t => {
      const r = await fetch('/passkey/options', { method:'POST', headers:{ 'Authorization':'Bearer '+t } });
      return { status: r.status, ok: r.ok };
    }, token);
    assert.strictEqual(res.status, 200);
    assert.ok(res.ok);
  });
});