const { exec } = require('child_process');
const assert = require('assert');
describe('数据库表结构', function() {
  it('package.json sql脚本能正常输出表名', function(done) {
    exec('sqlite3 ./users.db .tables', { cwd: __dirname + '/..' }, (err, stdout, stderr) => {
      assert.ifError(err);
      // 假设至少有一个表名输出
      assert.ok(stdout.trim().length > 0, '应有表名输出');
      done();
    });
  });
}); 