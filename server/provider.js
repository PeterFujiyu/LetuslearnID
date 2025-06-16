import Provider from 'oidc-provider';
import { getAllClients, getUserByName } from './lib/db.js';
import { createJWKSet } from './lib/keys.js';
import { URL } from 'node:url';

export async function initOIDCProvider(issuer) {
  /* ------------------------------------------------------------------
   * 1. 读取数据库客户端配置 → 转成 oidc-provider “静态客户端”
   * ----------------------------------------------------------------*/
  const dbClients = await getAllClients();
  const clients = dbClients.map((c) => ({
    client_id: c.client_id,
    client_secret: c.client_secret,
    redirect_uris: JSON.parse(c.redirect_uris),
    response_types: ['code'],
    grant_types: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_method:
      c.token_endpoint_auth_method || 'client_secret_post',
    scope: c.scopes,
  }));

  /* ------------------------------------------------------------------
   * 2. 生成服务端 JWK Set（RSA / EC / EdDSA）
   * ----------------------------------------------------------------*/
  const jwks = await createJWKSet();

  /* ------------------------------------------------------------------
   * 3. findAccount() → sub 映射到数据库用户信息
   * ----------------------------------------------------------------*/
  const findAccount = async (_ctx, id) => ({
    accountId: id,
    async claims() {
      const user = await getUserByName(id);
      return {
        sub: user.username,
        name: user.username,
        email: user.email,
        org: 'Letuslearn',
      };
    },
  });

  /* ------------------------------------------------------------------
   * 4. provider 主配置（不要包含 proxy=true）
   * ----------------------------------------------------------------*/
  const configuration = {
    clients,
    jwks,
    cookies: {
      keys: [process.env.COOKIE_KEY_1, process.env.COOKIE_KEY_2],
    },
    findAccount,
    claims: {
      openid: ['sub'],
      profile: ['name', 'org'],
      email: ['email'],
    },
    features: {
      devInteractions: { enabled: false },
      rpInitiatedLogout: { enabled: true },
      introspection: { enabled: true },
      revocation: { enabled: true },
    },
    ttl: {
      AccessToken: 3600, // 1 h
      IdToken: 3600,
      RefreshToken: 60 * 60 * 24 * 30, // 30 d
    },
  };

  /* ------------------------------------------------------------------
   * 5. 实例化 provider
   * ----------------------------------------------------------------*/
  const oidc = new Provider(issuer, configuration);

  /* ------------------------------------------------------------------
   * 6. 反向代理支持
   *    - oidc.proxy 告诉框架：信任 X-Forwarded-* 头
   *    - 由于某些环境头部不全，兜底把 ctx.secure 设成 true，
   *      从而强制发现文档全部输出 https://
   * ----------------------------------------------------------------*/
  oidc.proxy = true;

  // ⬇︎ 额外兜底：始终把 ctx.secure 设为 true，避免返回 http:// 端点
  oidc.use(async (ctx, next) => {
    ctx.secure = true; // 强制当作 HTTPS
    await next();
  });

  /* ------------------------------------------------------------------
   * 7. 调试日志
   * ----------------------------------------------------------------*/
  console.log('>> OIDC Provider issuer =', oidc.issuer);

  // 打印关键端点，确保都是 https://
  const discovery = oidc.urlFor('discovery');
  console.log('>> discovery url         =', discovery);
  console.log('>> authorization endpoint =', new URL('/auth', issuer).href);

  return oidc;
}
