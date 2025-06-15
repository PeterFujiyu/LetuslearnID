import jwt from 'jsonwebtoken';

async function loginToSso(db, username) {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  const payload = { sub: username, org: 'Letuslearn', app: 'LetuslearnID' };
  return jwt.sign(payload, secret, { expiresIn: '1h' });
}

export { loginToSso };
