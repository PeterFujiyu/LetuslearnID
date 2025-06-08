import { promisify } from 'util';
import jwt from 'jsonwebtoken';

async function loginToSso(db, username) {
  const get = promisify(db.get.bind(db));
  const cfg = await get('SELECT * FROM oidcauth LIMIT 1');
  if (!cfg) return null;
  const payload = {};
  payload[cfg.username_key] = username;
  payload.org = cfg.org_name;
  payload.app = cfg.app_name;
  return jwt.sign(payload, cfg.client_secret, { expiresIn: '1h' });
}

export { loginToSso };
