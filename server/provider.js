import Provider from 'oidc-provider';
import { getAllClients, getUserByName } from './lib/db.js';
import { createJWKSet } from './lib/keys.js';

export async function initOIDCProvider(issuer) {
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

  const jwks = await createJWKSet();

  const configuration = {
    clients,
    jwks,
    cookies: {
      keys: [process.env.COOKIE_KEY_1, process.env.COOKIE_KEY_2],
    },
    findAccount: async (ctx, id) => ({
      accountId: id,
      async claims() {
        const u = await getUserByName(id);
        return {
          sub: u.username,
          name: u.username,
          email: u.email,
          org: 'Letuslearn',
        };
      },
    }),
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
      AccessToken: 3600,
      IdToken: 3600,
      RefreshToken: 60 * 60 * 24 * 30,
    },
    proxy: true,
  };
  // temp log
  const discovery = oidc.discovery;
  console.log('>> discovery.issuer              =', discovery.issuer);
  console.log('>> discovery.authorization_endpoint =', discovery.authorization_endpoint);
  return new Provider(issuer, configuration);
}
