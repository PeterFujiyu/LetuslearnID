import Provider from 'oidc-provider';
import { getAllClients, getUserByName } from './lib/db.js';
import { createJWKSet } from './lib/keys.js';

export async function initOIDCProvider(issuer) {
  // 1) 读取数据库中的所有已注册客户端
  const dbClients = await getAllClients();
  const clients = dbClients.map(c => ({
    client_id: c.client_id,
    client_secret: c.client_secret,
    redirect_uris: JSON.parse(c.redirect_uris),
    response_types: ['code'],
    grant_types: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_method: c.token_endpoint_auth_method || 'client_secret_post',
    scope: c.scopes,
  }));

  // 2) 生成 JWK Set（RSA/EC/EdDSA 等）
  const jwks = await createJWKSet();

  // 3) 账号映射函数，让 provider 能把 sub → 用户信息
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

  // 4) provider 主配置（**不要再放 proxy: true**）
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
      introspection:    { enabled: true },
      revocation:       { enabled: true },
    },
    ttl: {
      AccessToken: 3600,               // 1 h
      IdToken:    3600,
      RefreshToken: 60 * 60 * 24 * 30, // 30 d
    },
  };

  // 5) 实例化 provider
  const oidc = new Provider(issuer, configuration);

  // 6) 告诉 oidc-provider：我们在受信任的反向代理之后
  oidc.proxy = true;

  // 7) 可选调试日志
  console.log('>> OIDC Provider issuer =', oidc.issuer);

  return oidc;
}
