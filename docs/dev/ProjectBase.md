# letuslearn.now 统一账号系统

本文档规划了在 **letuslearn.now** 域名下构建统一账号系统的总体思路。该系统将允许用户只使用一个账号即可访问所有子服务，其中文件存储服务 [AList](https://cloud.letuslearn.now) 已经部署完成。

## 技术栈

1. **后端框架**：采用 **Node.js** 搭配 **Express**，以获得轻量而灵活的服务端实现。
2. **数据库**：使用 **PostgreSQL**，可在轻量开发阶段先使用 SQLite，后续快速转向 PostgreSQL。
3. **身份验证**：基于 **JWT**（JSON Web Token）实现无状态认证，如有需要可扩展支持 OAuth 2.0。
4. **反向代理**：通过 **Nginx** 进行 HTTPS 终端处理及后端服务转发。
5. **前端**：使用 **React** 构建现代化的用户界面。

## 核心功能

1. **单点登录（SSO）**：用户只需注册和登录一次即可访问所有子域，包括 AList 及未来的新服务。
2. **统一用户数据库**：所有用户信息集中存储在 PostgreSQL 中，并提供 API 处理注册、登录、资料管理和权限等操作。
3. **令牌认证**：登录成功后颁发 JWT，子域通过请求头或 Cookie 验证令牌，完成跨服务的统一鉴权。
4. **角色管理**：实现多角色（如管理员、普通用户）机制，按角色控制不同服务的访问级别。用户组可继承其他组权限，首个注册用户自动获得管理员权限，可通过后台界面管理组与成员。
5. **AList 集成**：通过 API 回调或类似 OAuth 的插件，将 AList 的登录验证交由统一账号系统处理。
6. **WebAuthn 支持**：注册通行密钥，自动登录时通过 WebAuthn 验证设备。

## Preview: OIDC 单点登录

首次启动时会创建 `oidc_auth`、`oidc_clients` 与 `oidc_keys` 三张表，自动生成客户端与签名密钥。后续可通过 `/admin/clients` 接口添加更多客户端。
登录成功后服务器会据此向 OIDC 端点发放标准 Token，前端即可完成单点登录。

## 部署考虑

- **Docker**：利用 Docker 打包 Node.js 服务、数据库以及其他依赖，实现一致的部署环境。
- **HTTPS**：使用如 Let’s Encrypt 的 TLS 证书，保证通信安全。
- **可扩展性**：API 设计采用模块化路由，便于未来新增服务。
- **代码结构**：普通用户的登录、验证及凭据保存等接口已集中到 `server/users.js`，更易于维护。
- **Nginx 示例配置**：仓库 `docs/sites-nginx.conf` 提供虚拟主机示例，可参考部署；反向代理需传递 `X-Forwarded-Proto` 头以便 WebAuthn 正确识别 HTTPS。
- **监控与日志**：使用 **Winston** 等日志工具及 **Prometheus** 之类的监控方案，跟踪系统状态。

## 后续步骤

1. 建立 Git 仓库结构，按 server、client 与部署脚本等目录分开管理。
2. 初始化 Express 服务并连接 SQLite，未来可以迁移至 PostgreSQL。
4. 实现基础的注册与登录接口。
5. 配置 AList，使其通过该统一认证机制完成登录验证。
6. 提供账户设置页，可在其中修改登录密码。
7. 界面语言切换后保持全站一致，设置页右上角显示当前用户名称，并提供管理、登出及书签快捷入口。

## 目录结构

- `server/` — REST API 代码以及 Mocha 测试
- `client/` — React 引擎的登录和账户设置页
- `i18n/` — 翻译文件（已包含中英文版本）
- `docs/` — 开发设计文档

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
测试过程中使用内存版 SQLite，数据库会在所有用例执行结束后统一关闭，编写新用例时无需手动关闭连接。

仅运行单元测试：

```bash
npm run unit
```

如果只需运行 e2e 测试：

```bash
npm run e2e
```

新增 `passkey.test.js` 用于覆盖通行密钥相关接口，运行 `npm test` 会一并执行。
OIDC 相关配置和登录流程也在 `oidc.test.js` 覆盖，无需单独操作。

## API 说明

### `POST /logout`

请求体需包含浏览器指纹 `fingerprint`，并在 `Authorization` 头中携带登录 token。服务器会删除该指纹的会话并将 token 标记为失效，成功时返回：

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

当字段缺失时会返回 400 状态码并记录错误信息，而不再输出完整的堆栈日志。若 WebAuthn 验证未通过也会返回相同的 400 状态码，不会再出现 "toString" 相关异常。由于注册选项采用 `userVerification: 'preferred'`，后端验证阶段已关闭强制 `requireUserVerification`，从而兼容未提供用户验证信息的设备。

### OIDC 标准端点

系统现已引入 oidc-provider，提供标准的 `/oidc/.well-known/openid-configuration`、`/oidc/auth`、`/oidc/token` 等端点。
客户端应按 OIDC 流程跳转到 `/oidc/auth` 取得 `code`，随后在 `/oidc/token` 交换 `access_token`。
为保证生产环境安全，服务器在初始化 OIDC Provider 时关闭了 `devInteractions` 开发界面，相关配置位于 `server/index.js`。
从当前版本开始，OIDC Provider 在启动时会自动生成 RSA 密钥对用于签名，无需再读取 `jwt_key` 字段。

### 前端路径问题

早期前端跳转大量使用相对路径，复用提示页时会出现如 `/success/index.html?next=manage.html` 导致跳转到 `/success/manage.html` 的情况。现已统一改为绝对路径，并在读取 `next` 参数时补全 `/` 前缀，避免目录混淆。

### 管理界面

管理员通过 `/manage` 链接进入后台，随后的 `/admin/` 页面提供图形化界面管理用户和用户组。新版界面加入了 “SQL CLI” 区域，可直接输入 SQL 语句并查看执行结果，并新增 `.tables` 命令用于列出当前所有数据表。点击用户旁的 `Edit` 按钮可修改密码、关闭两步验证或通行密钥，并调整所属组。若需要临时验证码，可使用 `Code` 按钮立即获取；若数据库中不存在有效验证码则会自动创建一条。用户组列表支持在线修改名称、父组及权限字符串，也可新增新的用户组。

管理界面现已支持多语言切换，编辑表单提供“保存更改”和“取消”按钮，可在放弃时不保存修改。


## 未来工作

为了更好的拥有扩展性，项目计划在资源允许时将数据库从 SQLite 迁移到 PostgreSQL，此部分由于资源限制暂列为技术债。

