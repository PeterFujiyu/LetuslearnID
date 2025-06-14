# LetuslearnID

LetuslearnID 是一个简单轻量的账户管理服务器，基于 [Express](https://expressjs.com/) 实现。为了减少内存占用，默认使用 SQLite 存储用户数据，同时提供 React 前端页面及多语言支持。
支持 TOTP 双因素认证，可在设置页进入独立管理界面。启用或更新时会展示二维码并生成 12 个一次性备用代码，确认保存后需输入一次验证码确保配置正确，后续更新、关闭及重新生成备用代码都需要输入 TOTP 或备份代码。
重新生成备用代码时仅在确认后才会真正写入数据库，取消则不会产生变更。所有需要输入验证码的页面均增加“取消”按钮，可随时放弃操作回到设置页或登录页。

更多技术细节请参见 [docs/dev/ProjectBase.md](docs/dev/ProjectBase.md)。

服务启动后可访问 [http://localhost:3000/](http://localhost:3000/) 以打开登录页。

后端代码现已完全采用 ES Module 编写，如需在脚本中引用请使用 `import` 语法。

## 安装

### 快速开始

若已安装 Docker，可直接运行下列命令启动 PostgreSQL、LetuslearnID 及 AList：

```bash
docker compose up -d
```

随后访问 `http://localhost:3000/` 即可体验。

```bash
# Install node 20 on Ubuntu
sudo apt update && sudo apt upgrade
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | bash
# choose one
source ~/.bashrc  # For bash
source ~/.zshrc   # For zsh
nvm install 20
nvm use 20
# install datebase
sudo apt install sqlite3
# install lib
sudo apt install libnss3
# install this project
cd server && npm install
cp emailconfig.example.json emailconfig.json
vim emailconfig.json # SMTP
```
首次安装会通过 Playwright 下载 Chromium 浏览器文件，仅占用较小空间，如需其他浏览器可手动执行 `npx playwright install`。

## 启动服务

可以通过以下环境变量来调整服务器行为：

- `ISSUER` — OIDC Issuer 地址，默认为 `https://id.letuslearn.now`
- `COOKIE_KEY_1`、`COOKIE_KEY_2` — 签名 Cookie 的随机值
- `JWT_SECRET` — SSO Token 签名密钥（默认 `dev-secret`）
- `PORT` — HTTP 服务端口（默认 `3000`）
- `DB_FILE` — SQLite 数据库文件路径（默认 `./server/users.db`）

在 `server` 目录下启动服务：

```bash
npm start
```

首次运行会依次询问部署域名和回调地址（如 `https://cloud.letuslearn.now/api/auth/sso_callback`），
系统会创建 `oidc_auth`、`oidc_clients` 及 `oidc_keys` 表并写入默认数据，
随后以 `OIDC 配置初次生成:` 打印包含客户端与密钥在内的完整配置。
从此版本开始，脚本会确保 `oidc_auth` 与 `oidc_clients` 表中的 `client_id` 与
`client_secret` 保持一致，避免多次初始化造成配置残留。
如需重新生成配置，可执行 `npm run resetoidc`，该命令会清空以上三张表后重新生成。

## 测试

运行单元和端到端测试：

```bash
npm test    # 包含单元以及 e2e 测试
```
若系统缺少 Playwright 运行所需的库，可参照终端提示安装。
测试会在内存中创建 SQLite 数据库，所有用例执行完毕后统一关闭，因而无需在单个测试中手动关闭连接。

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


启动后访问 `http://localhost:3000/oidc/index.html`，点击按钮即可跳转到 OIDC 授权页并在回调页显示令牌结果。系统会从 `oidc_clients` 表读取配置，并使用 `jose` 动态生成 RSA 密钥对。所有标准端点 `/auth`、`/token` 等均已启用，授权阶段可选择通过通行密钥或 TOTP 完成验证。

## Nginx 反向代理部署

若在生产环境通过 Nginx 终端 TLS，可按以下步骤让 OIDC 正确识别 HTTPS：

1. **显式设置 ISSUER**：

   ```bash
   export ISSUER=https://id.letuslearn.now
   ```

2. **启用 Provider 的 proxy**：在 `server/provider.js` 创建 Provider 时加入 `proxy: true`。

3. **Express 信任代理**：在 `server/index.js` 中调用 `app.set('trust proxy', true)` 以读取 `X-Forwarded-Proto`。

4. **Nginx 传递真实协议**：在示例配置 `docs/sites-nginx.conf` 的 `location /` 内加入 `proxy_set_header X-Forwarded-Proto https;`。

仅在 HTTPS 环境下，AList 等客户端才能按标准 OIDC 流程完成登录。


