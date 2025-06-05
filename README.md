# LetuslearnID

LetuslearnID 是一个简单轻量的账户管理服务器，基于 [Express](https://expressjs.com/) 实现。为了减少内存占用，默认使用 SQLite 存储用户数据，同时提供 React 前端页面及多语言支持。

## 目录结构

- `server/` — REST API 代码以及 Mocha 测试
- `client/` — React 引擎的登录和账户设置页
- `i18n/` — 翻译文件（已包含中英文版本）
- `docs/` — 开发设计文档

## 安装

```bash
cd server && npm install
```

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
登录和注册现在各自使用独立页面，成功或失败都会进入提示页再跳转，所有原先的弹窗已被替换。
登录表单允许设置 2-13 天的免登录时长，账户设置页面新增修改密码功能。

## 测试

运行单元和端到端测试：

```bash
npm test    # 包含单元以及 e2e 测试
```

如果只需运行 e2e 测试：

```bash
npm run e2e
```

## 未来工作

为了更好的拥有扩展性，项目将来计划将数据库移植自 SQLite 到 PostgreSQL，该任务由于资源限制已经创建为技术债。
