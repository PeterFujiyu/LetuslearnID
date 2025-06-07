# LetuslearnID

LetuslearnID 是一个简单轻量的账户管理服务器，基于 [Express](https://expressjs.com/) 实现。为了减少内存占用，默认使用 SQLite 存储用户数据，同时提供 React 前端页面及多语言支持。
支持 TOTP 双因素认证，可在设置页进入独立管理界面。启用或更新时会展示二维码并生成 12 个一次性备用代码，确认保存后需输入一次验证码确保配置正确，后续更新、关闭及重新生成备用代码都需要输入 TOTP 或备份代码。
重新生成备用代码后会显示备份列表，现在该页面也提供“取消”与“确认”按钮，方便用户在保存后直接返回设置页。所有需要输入验证码的页面均增加“取消”按钮，可随时放弃操作回到设置页或登录页。

## 目录结构

- `server/` — REST API 代码以及 Mocha 测试
- `client/` — React 引擎的登录和账户设置页
- `i18n/` — 翻译文件（已包含中英文版本）
- `docs/` — 开发设计文档

## 安装

```bash
cd server && npm install
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

服务启动后可访问 [http://localhost:3000/](http://localhost:3000/) 以打开登录页。
登录和注册现在各自使用独立页面，成功或失败都会进入提示页再跳转，所有原先的弹窗已被替换。页面按钮统一为黑色圆角样式并带有简易过渡动画（注册页返回登录改为灰色小字链接“已经拥有账户？”），标题会随所选语言自动更新。成功页面可通过 `msg` 参数指定翻译键，如 `msg=success` 将在语言文件中查找对应文本。
会话保持天数现在在账户设置页修改，保存后与浏览器指纹一同存入数据库实现自动登录。如启用通行密钥，会在保存设置时注册 WebAuthn 设备，且同一账户可绑定多个 passkey。后续自动登录会先进行设备验证。登录表单只需输入用户名和密码，账户设置页面仍提供修改密码功能。启用后，在 TOTP 验证页面会额外显示“Use passkey?”，即便没有保存会话也能凭临时 token 获取选项并直接通过通行密钥完成登录。TOTP 确认页同样支持使用 passkey 再次验证，无需输入验证码。
现在所有页面都会记住最近选择的语言，设置页右上角显示登录账户并提供快捷菜单，可快速跳转到管理界面、登出以及用户自定义的书签。

登出时页面会调用 `/logout`，携带当前指纹并在请求头中附加 token。服务器删除该指纹的会话记录并使 token 失效，浏览器随后需执行 `localStorage.removeItem('token')` 并返回登录页。

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

新增 `passkey.test.js` 用于覆盖通行密钥相关接口，运行 `npm test` 会一并执行。

## API 说明

### `POST /logout`

请求体需包含浏览器指纹 `fingerprint`，并在 `Authorization` 头中携带登录 token。
服务器会删除该指纹的会话并将 token 标记为失效，成功时返回：

```json

{ "message": "logged out" }
```

### `GET /profile`

返回当前登录用户的基础信息，包含已注册的通行密钥：

```json
{
  "id": 1,
  "username": "alice",
  "totp": false,
  "passkeys": []
}
```

### `POST /passkey/register`

验证并绑定用户的通行密钥。请求体需包含 WebAuthn 返回的 `id`、`rawId`、`response` 及 `type` 字段。
若字段缺失或验证失败，服务器将返回：

```json
{ "error": "Verification failed" }
```

当字段缺失时会返回 400 状态码并记录错误信息，而不再输出完整的堆栈日志。
若 WebAuthn 验证未通过也会返回相同的 400 状态码，不会再出现 "toString" 相关异常。
由于注册选项采用 `userVerification: 'preferred'`，后端验证阶段已关闭强制 `requireUserVerification`，
从而兼容未提供用户验证信息的设备。

## 未来工作

为了更好的拥有扩展性，项目将来计划将数据库移植自 SQLite 到 PostgreSQL，该任务由于资源限制已经创建为技术债。
