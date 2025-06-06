const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { promisify } = require('util');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { authenticator } = require('otplib');

const app = express();
app.use(express.json());
const challenges = {};
const clientDir = path.join(__dirname, "..", "client");
app.use(express.static(clientDir));
app.use('/i18n', express.static(path.join(__dirname, '..', 'i18n')));
app.get("/", (req, res) => {
  res.sendFile(path.join(clientDir, "index", "index.html"));
});

const dbFile = process.env.DB_FILE || path.join(__dirname, 'users.db');
const db = new sqlite3.Database(dbFile);


// Initialize user table if it doesn't exist
const initDb = () => {
  const query = `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    credential_id TEXT,
    passkey_public TEXT,
    counter INTEGER DEFAULT 0,
    totp_secret TEXT,
    backup_codes TEXT
  )`;
  const sessionQuery = `CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    fingerprint TEXT,
    expires_at INTEGER
  )`;
  const alters = [
    'ALTER TABLE users ADD COLUMN totp_secret TEXT',
    'ALTER TABLE users ADD COLUMN backup_codes TEXT'
  ];
  return Promise.all([
    promisify(db.run.bind(db))(query),
    promisify(db.run.bind(db))(sessionQuery),
    ...alters.map(a => promisify(db.run.bind(db))(a).catch(() => {}))
  ]);
};

const getUserByUsername = async (username) => {
  const query = 'SELECT * FROM users WHERE username = ?';
  return promisify(db.get.bind(db))(query, username);
};

const createUser = async (username, passwordHash) => {
  const query = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
  return promisify(db.run.bind(db))(query, username, passwordHash);
};

const createSession = async (userId, fingerprint, expiresAt) => {
  const query = 'INSERT INTO sessions (user_id, fingerprint, expires_at) VALUES (?,?,?)';
  return promisify(db.run.bind(db))(query, userId, fingerprint, expiresAt);
};

const getValidSession = async (fingerprint) => {
  const query = 'SELECT * FROM sessions WHERE fingerprint = ? AND expires_at > ? ORDER BY expires_at DESC LIMIT 1';
  return promisify(db.get.bind(db))(query, fingerprint, Date.now());
};

const deleteSession = async (fingerprint) => {
  const query = 'DELETE FROM sessions WHERE fingerprint = ?';
  return promisify(db.run.bind(db))(query, fingerprint);
};

const createPasskey = async (userId, credId, publicKey, counter) => {
  const q = 'UPDATE users SET credential_id=?, passkey_public=?, counter=? WHERE id=?';
  return promisify(db.run.bind(db))(q, credId, publicKey, counter, userId);
};

const getUserByCredId = async (credId) => {
  const q = 'SELECT * FROM users WHERE credential_id = ?';
  return promisify(db.get.bind(db))(q, credId);
};

const updateUserPassword = async (id, passwordHash) => {
  const query = 'UPDATE users SET password_hash = ? WHERE id = ?';
  return promisify(db.run.bind(db))(query, passwordHash, id);
};

const setTotpSecret = async (id, secret, codes) => {
  const q = 'UPDATE users SET totp_secret=?, backup_codes=? WHERE id=?';
  return promisify(db.run.bind(db))(q, secret, codes, id);
};

const updateBackupCodes = async (id, codes) => {
  const q = 'UPDATE users SET backup_codes=? WHERE id=?';
  return promisify(db.run.bind(db))(q, codes, id);
};

// JWT secret; in production use environment variable
const SECRET = process.env.JWT_SECRET || 'dev-secret';

const revokedTokens = new Set();

const generateToken = (user, days) => {
  const opts = days && days > 1 && days < 14 ? { expiresIn: `${days}d` } : { expiresIn: '1h' };
  return jwt.sign({ id: user.id, username: user.username }, SECRET, opts);
};

const authenticateToken = (req, res, next) => {
  const auth = req.headers['authorization'];
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  if (revokedTokens.has(token)) return res.status(403).json({ error: 'Invalid token' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  try {
    const existing = await getUserByUsername(username);
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }
    const hash = await bcrypt.hash(password, 10);
    await createUser(username, hash);
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password, rememberDays, fingerprint } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  try {
    const user = await getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.totp_secret) {
      const temp = jwt.sign({ id: user.id, username: user.username, tfa: true, remember: rememberDays, fingerprint }, SECRET, { expiresIn: '5m' });
      return res.json({ tfa: true, temp });
    }
    let days = rememberDays;
    if (fingerprint) {
      const sess = await getValidSession(fingerprint);
      if (sess && sess.user_id === user.id) {
        days = Math.max(1, Math.round((sess.expires_at - Date.now()) / 86400000));
      }
    }
    const token = generateToken(user, days);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await getUserByUsername(req.user.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ id: user.id, username: user.username, totp: !!user.totp_secret });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Old and new passwords are required' });
  }
  try {
    const user = await getUserByUsername(req.user.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(oldPassword, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const hash = await bcrypt.hash(newPassword, 10);
    await updateUserPassword(user.id, hash);
    res.json({ message: 'Password changed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const genCodes = () => {
  const arr = [];
  for (let i = 0; i < 12; i++) {
    arr.push(Math.random().toString(36).slice(-8));
  }
  return arr;
};

const verifyTotp = async (user, code) => {
  let valid = authenticator.verify({ token: code, secret: user.totp_secret });
  let codes = [];
  if (!valid && user.backup_codes) {
    codes = JSON.parse(user.backup_codes);
    const idx = codes.indexOf(code);
    if (idx > -1) {
      valid = true;
      codes.splice(idx, 1);
      await updateBackupCodes(user.id, JSON.stringify(codes));
    }
  }
  return valid;
};

const disableTotp = async (id) => {
  await setTotpSecret(id, null, null);
};

app.post('/totp/setup', authenticateToken, async (req, res) => {
  try {
    const secret = authenticator.generateSecret();
    const url = authenticator.keyuri(req.user.username, 'LetuslearnID', secret);
    const codes = genCodes();
    await setTotpSecret(req.user.id, secret, JSON.stringify(codes));
    res.json({ secret, url, codes });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/totp/verify', async (req, res) => {
  const { token, code } = req.body;
  if (!token || !code) return res.status(400).json({ error: 'Missing data' });
  try {
    const payload = jwt.verify(token, SECRET);
    if (!payload.tfa) return res.status(400).json({ error: 'Invalid token' });
    const user = await getUserByUsername(payload.username);
    if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
    let valid = authenticator.verify({ token: code, secret: user.totp_secret });
    let codes = [];
    if (!valid && user.backup_codes) {
      codes = JSON.parse(user.backup_codes);
      const idx = codes.indexOf(code);
      if (idx > -1) {
        valid = true;
        codes.splice(idx, 1);
        await updateBackupCodes(user.id, JSON.stringify(codes));
      }
    }
    if (!valid) return res.status(401).json({ error: 'Invalid code' });
    let days = payload.remember;
    if (payload.fingerprint) {
      const sess = await getValidSession(payload.fingerprint);
      if (sess && sess.user_id === user.id) {
        days = Math.max(1, Math.round((sess.expires_at - Date.now()) / 86400000));
      }
    }
    const final = generateToken(user, days);
    res.json({ token: final });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Invalid token' });
  }
});

app.post('/totp/regenerate', authenticateToken, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Missing code' });
  try {
    const user = await getUserByUsername(req.user.username);
    if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
    const valid = await verifyTotp(user, code);
    if (!valid) return res.status(401).json({ error: 'Invalid code' });
    const codes = genCodes();
    await updateBackupCodes(req.user.id, JSON.stringify(codes));
    res.json({ codes });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/totp/check', authenticateToken, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Missing code' });
  try {
    const user = await getUserByUsername(req.user.username);
    if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
    const valid = await verifyTotp(user, code);
    if (!valid) return res.status(401).json({ error: 'Invalid code' });
    res.json({ message: 'ok' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/totp/cancel', authenticateToken, async (req, res) => {
  try {
    await disableTotp(req.user.id);
    res.json({ message: 'cancelled' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/totp/disable', authenticateToken, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Missing code' });
  try {
    const user = await getUserByUsername(req.user.username);
    if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
    const valid = await verifyTotp(user, code);
    if (!valid) return res.status(401).json({ error: 'Invalid code' });
    await disableTotp(user.id);
    res.json({ message: 'disabled' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/totp/update', authenticateToken, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Missing code' });
  try {
    const user = await getUserByUsername(req.user.username);
    if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
    const valid = await verifyTotp(user, code);
    if (!valid) return res.status(401).json({ error: 'Invalid code' });
    const secret = authenticator.generateSecret();
    const url = authenticator.keyuri(req.user.username, 'LetuslearnID', secret);
    const codes = genCodes();
    await setTotpSecret(user.id, secret, JSON.stringify(codes));
    res.json({ secret, url, codes });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/session', authenticateToken, async (req, res) => {
  const { fingerprint, days } = req.body;
  if (!fingerprint || !days) return res.status(400).json({ error: 'Missing data' });
  const expiresAt = Date.now() + Number(days) * 86400000;
  try {
    await createSession(req.user.id, fingerprint, expiresAt);
    res.json({ message: 'session saved' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/passkey/options', authenticateToken, async (req, res) => {
  try {
    const user = await getUserByUsername(req.user.username);
    const options = generateRegistrationOptions({
      rpName: 'LetuslearnID',
      rpID: req.headers.host.split(':')[0],
      userID: Buffer.from(String(user.id)),
      userName: user.username
    });
    challenges[user.username] = options.challenge;
    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/passkey/register', authenticateToken, async (req, res) => {
  try {
    const expectedChallenge = challenges[req.user.username];
    if (!expectedChallenge) return res.status(400).json({ error: 'No challenge' });
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: `http://${req.headers.host}`,
      expectedRPID: req.headers.host.split(':')[0]
    });
    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
    await createPasskey(req.user.id, credentialID.toString('base64url'), credentialPublicKey.toString('base64'), counter);
    delete challenges[req.user.username];
    res.json({ message: 'registered' });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Verification failed' });
  }
});

app.post('/passkey/auth-options', async (req, res) => {
  const { fingerprint } = req.body;
  if (!fingerprint) return res.status(400).json({ error: 'Missing fingerprint' });
  try {
    const sess = await getValidSession(fingerprint);
    if (!sess) return res.status(404).json({ error: 'Not found' });
    const user = await promisify(db.get.bind(db))('SELECT * FROM users WHERE id = ?', sess.user_id);
    if (!user || !user.credential_id) return res.status(404).json({ error: 'No passkey' });
    const options = generateAuthenticationOptions({
      rpID: req.headers.host.split(':')[0],
      allowCredentials: [{ id: Buffer.from(user.credential_id, 'base64url'), type: 'public-key' }]
    });
    challenges[fingerprint] = { challenge: options.challenge, sess };
    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/passkey/auth', async (req, res) => {
  const { fingerprint } = req.query;
  if (!fingerprint) return res.status(400).json({ error: 'Missing fingerprint' });
  const data = challenges[fingerprint];
  if (!data) return res.status(400).json({ error: 'No challenge' });
  try {
    const user = await getUserByCredId(Buffer.from(req.body.rawId, 'base64').toString('base64url'));
    if (!user) return res.status(404).json({ error: 'Unknown credential' });
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: data.challenge,
      expectedOrigin: `http://${req.headers.host}`,
      expectedRPID: req.headers.host.split(':')[0],
      authenticator: {
        credentialID: Buffer.from(user.credential_id, 'base64url'),
        credentialPublicKey: Buffer.from(user.passkey_public, 'base64'),
        counter: user.counter
      }
    });
    await createPasskey(user.id, user.credential_id, user.passkey_public, verification.authenticationInfo.newCounter);
    const daysLeft = Math.max(1, Math.round((data.sess.expires_at - Date.now()) / 86400000));
    const token = generateToken(user, daysLeft);
    delete challenges[fingerprint];
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Verification failed' });
  }
});

app.post('/passkey/remove', authenticateToken, async (req, res) => {
  try {
    await createPasskey(req.user.id, null, null, 0);
    res.json({ message: 'removed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/logout', authenticateToken, async (req, res) => {
  const { fingerprint } = req.body;
  if (!fingerprint) return res.status(400).json({ error: 'Missing fingerprint' });
  try {
    await deleteSession(fingerprint);
    const auth = req.headers['authorization'];
    const token = auth && auth.split(' ')[1];
    if (token) revokedTokens.add(token);
    res.json({ message: 'logged out' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/auto-login', async (req, res) => {
  const { fp } = req.query;
  if (!fp) return res.status(400).json({ error: 'Missing fingerprint' });
  try {
    const sess = await getValidSession(fp);
    if (!sess) return res.status(404).json({ error: 'Not found' });
    const user = await promisify(db.get.bind(db))('SELECT * FROM users WHERE id = ?', sess.user_id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const daysLeft = Math.max(1, Math.round((sess.expires_at - Date.now()) / 86400000));
    const token = generateToken(user, daysLeft);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});


initDb().then(() => {
  if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  }
}).catch((err) => {
  console.error('Failed to initialize database', err);
});

module.exports = { app, initDb, db };
