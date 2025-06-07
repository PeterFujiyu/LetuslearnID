# LetuslearnID

LetuslearnID 是一个简单轻量的账户管理服务器，基于 [Express](https://expressjs.com/) 实现。为了减少内存占用，默认使用 SQLite 存储用户数据，同时提供 React 前端页面及多语言支持。
支持 TOTP 双因素认证，可在设置页进入独立管理界面。启用或更新时会展示二维码并生成 12 个一次性备用代码，确认保存后需输入一次验证码确保配置正确，后续更新、关闭及重新生成备用代码都需要输入 TOTP 或备份代码。
重新生成备用代码时仅在确认后才会真正写入数据库，取消则不会产生变更。所有需要输入验证码的页面均增加“取消”按钮，可随时放弃操作回到设置页或登录页。

更多技术细节与安装说明请参见 [docs/dev/ProjectBase.md](docs/dev/ProjectBase.md)。

服务启动后可访问 [http://localhost:3000/](http://localhost:3000/) 以打开登录页。
登录和注册现在各自使用独立页面，成功或失败都会进入提示页再跳转，所有原先的弹窗已被替换。页面按钮统一为黑色圆角样式并带有简易过渡动画（注册页返回登录改为灰色小字链接“已经拥有账户？”），标题会随所选语言自动更新。成功页面可通过 `msg` 参数指定翻译键，如 `msg=success` 将在语言文件中查找对应文本。
修改邮箱时验证码输入也改为单独页面，不再使用浏览器弹窗。
会话保持天数现在在账户设置页修改，保存后与浏览器指纹一同存入数据库实现自动登录。如启用通行密钥，会在保存设置时注册 WebAuthn 设备，且同一账户可绑定多个 passkey。后续自动登录会先进行设备验证。登录表单首先仅输入用户名，点击“Login”后跳转到密码页，该页面下方提供“Use passkey?” 按钮，可直接通过通行密钥完成登录，账户设置页面仍提供修改密码功能。启用后，在 TOTP 验证页面会额外显示“Use passkey?”，即便没有保存会话也能凭临时 token 获取选项并直接通过通行密钥完成登录。TOTP 确认页在创建或更新 TOTP 时不会提供该选项。
启用或关闭通行密钥也会进入确认页，避免误操作。
现在所有页面都会记住最近选择的语言，设置页右上角显示登录账户并提供快捷菜单，可快速跳转到管理界面、登出以及用户自定义的书签。

登出时页面会调用 `/logout`，携带当前指纹并在请求头中附加 token。服务器删除该指纹的会话记录并使 token 失效，浏览器随后需执行 `localStorage.removeItem('token')` 并返回登录页。

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

