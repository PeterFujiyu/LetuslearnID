import { generateKeyPair, exportJWK } from 'jose';
import crypto from 'crypto';
import { get, run } from './db.js';

export async function createJWKSet() {
  if (process.env.JWT_PRIVATE) {
    return { keys: [JSON.parse(process.env.JWT_PRIVATE)] };
  }
  const row = await get('SELECT key FROM oidc_keys LIMIT 1');
  if (row) {
    return { keys: [JSON.parse(row.key)] };
  }
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  privateJwk.use = 'sig';
  privateJwk.alg = 'RS256';
  privateJwk.kid = crypto.randomUUID();
  await run('INSERT INTO oidc_keys (kid,kty,alg,use,key) VALUES (?,?,?,?,?)',
    privateJwk.kid, privateJwk.kty, privateJwk.alg, privateJwk.use, JSON.stringify(privateJwk));
  console.log('OIDC Key 初次生成:', { kid: privateJwk.kid });
  return { keys: [privateJwk] };
}
