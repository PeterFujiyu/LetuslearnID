import { generateKeyPair, exportJWK } from 'jose';

export async function createJWKSet() {
  if (process.env.JWT_PRIVATE) {
    return { keys: [JSON.parse(process.env.JWT_PRIVATE)] };
  }
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  privateJwk.use = 'sig';
  privateJwk.alg = 'RS256';
  return { keys: [privateJwk] };
}
