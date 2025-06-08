import { sendCode } from './email.js';
import assert from 'assert';

describe('邮件发送功能', function() {
  this.timeout(10000); // 邮件发送可能较慢，设为10秒
  const code = process.env.TEST_CODE || 'test';
  const email = process.env.TEST_EMAIL;
  it('应该成功发送邮件', async function() {
    if (!email) {
      // 没有 email 就跳过
      this.skip();
    }
    let error = null;
    try {
      await sendCode(email, code, 'mocha-test');
    } catch (err) {
      error = err;
    }
    assert.strictEqual(error, null, error ? error.message : '');
  });
});
