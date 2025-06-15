import { generateKeyPair, exportJWK } from 'jose';

export async function createJWKSet() {
  if (process.env.JWT_PRIVATE) {
    return { keys: [JSON.parse(process.env.JWT_PUBLIC)] };
  }
  const { privateKey } = await generateKeyPair('RS256');
  const publicJwk = await exportJWK(privateKey);
  publicJwk.use = 'sig';
  publicJwk.alg = 'RS256';
  return { keys: [publicJwk] };
}
