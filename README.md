# LetuslearnID

LetuslearnID 是一个简单轻量的账户管理服务器，基于 [Express](https://expressjs.com/) 实现。为了减少内存占用，默认使用 SQLite 存储用户数据，同时提供 React 前端页面及多语言支持。
支持 TOTP 双因素认证，可在设置页进入独立管理界面。启用或更新时会展示二维码并生成 12 个一次性备用代码，确认保存后需输入一次验证码确保配置正确，后续更新、关闭及重新生成备用代码都需要输入 TOTP 或备份代码。
重新生成备用代码时仅在确认后才会真正写入数据库，取消则不会产生变更。所有需要输入验证码的页面均增加“取消”按钮，可随时放弃操作回到设置页或登录页。

更多技术细节请参见 [docs/dev/ProjectBase.md](docs/dev/ProjectBase.md)。

服务启动后可访问 [http://localhost:3000/](http://localhost:3000/) 以打开登录页。

## 安装

```bash
cd server && npm install
cp emailconfig.example.json emailconfig.json
vim emailconfig.json # 配置SMTP服务
```
首次安装会通过 Playwright 下载 Chromium 浏览器文件，仅占用较小空间，如需其他浏览器可手动执行 `npx playwright install`。

## 启动服务

可以通过以下环境变量来调整服务器行为：

- `JWT_SECRET` — JWT 签名密钥（默认 `dev-secret`）
- `PORT` — HTTP 服务端口（默认 `3000`）
- `DB_FILE` — SQLite 数据库文件路径（默认 `./server/users.db`）

在 `server` 目录下启动服务：

```bash
npm start
```

## 测试

运行单元和端到端测试：

```bash
npm test    # 包含单元以及 e2e 测试
```
若系统缺少 Playwright 运行所需的库，可参照终端提示安装。

仅运行单元测试：

```bash
npm run unit
```

如果只需运行 e2e 测试：

```bash
npm run e2e
```

## SMTP 配置

项目使用 `nodemailer` 发送验证码邮件，相关设置存放在 `server/emailconfig.json`。示例如下：

```json
{
  "smtp": {
    "host": "smtp.example.com",
    "port": 465,
    "secure": true,
    "auth": { "user": "user@example.com", "pass": "password" }
  },
  "from": "noreply@example.com",
  "subject": "LetuslearnID verification code",
  "template": "Your verification code is {code}. IP: {ip}. If this wasn't you please ignore this email."
}
```

按需修改 `smtp` 字段以匹配实际的邮件服务器地址和凭据，即可在注册、找回凭据及修改邮箱时收到验证码邮件。

配置完成后，可运行下列命令验证 SMTP 是否可用：

```bash
cd server
TEST_CODE=123654 TEST_EMAIL=user@example.com npx mocha testemailsmtp.js
```

若邮件成功送达则表示配置正确。

