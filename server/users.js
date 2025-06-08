import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { promisify } from 'util';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { authenticator } from 'otplib';
import { sendCode } from './email.js';
import { loginToSso } from './sso.js';

function setupUserRoutes(app, db) {
  const challenges = {};
  const SECRET = process.env.JWT_SECRET || 'dev-secret';
  const revokedTokens = new Set();

  const verifyToken = (token) => new Promise((res, rej) => {
    if (!token || revokedTokens.has(token)) return rej(new Error('Invalid'));
    jwt.verify(token, SECRET, (err, user) => {
      if (err) return rej(err);
      res(user);
    });
  });

  const runStmt = (q, params=[]) => new Promise((res, rej) => {
    db.run(q, params, function(err){ if(err) rej(err); else res(this); });
  });

  const getUserByUsername = async (username) => {
    const query = 'SELECT * FROM users WHERE username = ?';
    return promisify(db.get.bind(db))(query, username);
  };

  const createUser = async (username, email, passwordHash) => {
    const query = 'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)';
    const stmt = await runStmt(query, [username, email, passwordHash]);
    const count = await promisify(db.get.bind(db))('SELECT COUNT(*) as c FROM users');
    const groupId = count.c === 1 ? 1 : 2; // first user becomes admin
    await runStmt('INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)', [stmt.lastID, groupId]);
    return stmt;
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

  const addPasskey = async (userId, credId, publicKey, counter) => {
    const q = 'INSERT INTO passkeys (user_id, credential_id, public_key, counter) VALUES (?,?,?,?)';
    return promisify(db.run.bind(db))(q, userId, credId, publicKey, counter);
  };

  const getPasskeysByUser = async (userId) => {
    const q = 'SELECT * FROM passkeys WHERE user_id=?';
    return promisify(db.all.bind(db))(q, userId);
  };

  const getPasskeyByCredId = async (credId) => {
    const q = 'SELECT * FROM passkeys WHERE credential_id=?';
    return promisify(db.get.bind(db))(q, credId);
  };

  const updatePasskeyCounter = async (credId, counter) => {
    const q = 'UPDATE passkeys SET counter=? WHERE credential_id=?';
    return promisify(db.run.bind(db))(q, counter, credId);
  };

  const removePasskey = async (userId, credId) => {
    if (credId) {
      const q = 'DELETE FROM passkeys WHERE user_id=? AND credential_id=?';
      return promisify(db.run.bind(db))(q, userId, credId);
    }
    const q = 'DELETE FROM passkeys WHERE user_id=?';
    return promisify(db.run.bind(db))(q, userId);
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

  const addPending = async (username, email, hash, code, action) => {
    const q = 'INSERT INTO pending_codes (username,email,password_hash,code,action,created_at) VALUES (?,?,?,?,?,?)';
    const stmt = await runStmt(q, [username, email, hash, code, action, Date.now()]);
    return stmt.lastID;
  };

  const getPending = async (id) => {
    const q = 'SELECT * FROM pending_codes WHERE id=?';
    return promisify(db.get.bind(db))(q, id);
  };

  const removePending = async (id) => {
    const q = 'DELETE FROM pending_codes WHERE id=?';
    return promisify(db.run.bind(db))(q, id);
  };

  const getVerifyCode = async (uid, ip) => {
    const q = 'SELECT * FROM verifycode WHERE user_id=? AND ip=? AND authorized=0 AND expires_at>? ORDER BY id DESC LIMIT 1';
    return promisify(db.get.bind(db))(q, uid, ip, Date.now());
  };

  const createVerifyCode = async (uid, ip, code) => {
    const q = 'INSERT INTO verifycode (user_id, ip, code, expires_at) VALUES (?,?,?,?)';
    return runStmt(q, [uid, ip, code, Date.now() + 600000]);
  };

  const markVerifyCode = async (id) => {
    const q = 'UPDATE verifycode SET authorized=1 WHERE id=?';
    return promisify(db.run.bind(db))(q, id);
  };

  const getOrCreateCode = async (uid, ip) => {
    const rec = await getVerifyCode(uid, ip);
    if (rec) return { code: rec.code, id: rec.id };
    const code = Math.floor(100000 + Math.random()*900000).toString();
    const stmt = await createVerifyCode(uid, ip, code);
    return { code, id: stmt.lastID };
  };

  const generateToken = (user, days, extra = {}) => {
    const opts = days && days > 1 && days < 14 ? { expiresIn: `${days}d` } : { expiresIn: '1h' };
    return jwt.sign({ id: user.id, username: user.username, ...extra }, SECRET, opts);
  };

  const authenticateToken = (req, res, next) => {
    const auth = req.headers['authorization'];
    const token = auth && auth.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    verifyToken(token).then(user => { req.user = user; next(); }).catch(() => res.status(403).json({ error: 'Invalid token' }));
  };

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

  // ----- Routes -----
  app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing data' });
    }
    try {
      const existing = await getUserByUsername(username);
      if (existing) return res.status(409).json({ error: 'User already exists' });
      const hash = await bcrypt.hash(password, 10);
      const { code } = await getOrCreateCode(0, req.ip);
      const id = await addPending(username, email, hash, code, 'register');
      sendCode(email, code, req.ip).catch(() => {});
      res.json({ id });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/register/verify', async (req, res) => {
    const { id, code } = req.body;
    if (!id || !code) return res.status(400).json({ error: 'Missing data' });
    try {
      const record = await getPending(id);
      if (!record || record.code !== code || record.action !== 'register') {
        return res.status(400).json({ error: 'Invalid code' });
      }
      await createUser(record.username, record.email, record.password_hash);
      await removePending(id);
      await promisify(db.run.bind(db))('UPDATE verifycode SET authorized=1 WHERE code=? AND ip=? AND authorized=0', record.code, req.ip);
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
      const sso = await loginToSso(db, user.username);
      res.json({ token, sso });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.get('/profile', authenticateToken, async (req, res) => {
    try {
      const user = await getUserByUsername(req.user.username);
      if (!user) return res.status(404).json({ error: 'User not found' });
      const keys = await getPasskeysByUser(user.id);
      const groups = await promisify(db.all.bind(db))(
        'SELECT g.name FROM user_groups ug JOIN groups g ON ug.group_id=g.id WHERE ug.user_id=?',
        user.id
      );
      res.json({
        id: user.id,
        username: user.username,
        totp: !!user.totp_secret,
        groups: groups.map(g=>g.name),
        passkeys: keys.map(k => k.credential_id)
      });
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

  app.post('/change-email', authenticateToken, async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Missing email' });
    try {
      const { code } = await getOrCreateCode(req.user.id, req.ip);
      const id = await addPending(req.user.username, email, null, code, 'change');
      sendCode(email, code, req.ip).catch(() => {});
      res.json({ id });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/change-email/verify', authenticateToken, async (req, res) => {
    const { id, code } = req.body;
    if (!id || !code) return res.status(400).json({ error: 'Missing data' });
    try {
      const record = await getPending(id);
      if (!record || record.code !== code || record.action !== 'change' || record.username !== req.user.username) {
        return res.status(400).json({ error: 'Invalid code' });
      }
      await promisify(db.run.bind(db))('UPDATE users SET email=? WHERE username=?', record.email, req.user.username);
      await removePending(id);
      await promisify(db.run.bind(db))('UPDATE verifycode SET authorized=1 WHERE code=? AND ip=? AND authorized=0', record.code, req.ip);
      res.json({ message: 'updated' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

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
      let valid = await verifyTotp(user, code);
      if (!valid) return res.status(401).json({ error: 'Invalid code' });
      let days = payload.remember;
      if (payload.fingerprint) {
        const sess = await getValidSession(payload.fingerprint);
        if (sess && sess.user_id === user.id) {
          days = Math.max(1, Math.round((sess.expires_at - Date.now()) / 86400000));
        }
      }
      const final = generateToken(user, days);
      const sso = await loginToSso(db, user.username);
      res.json({ token: final, sso });
    } catch (err) {
      console.error(err);
      res.status(400).json({ error: 'Invalid token' });
    }
  });

  app.post('/totp/regenerate', authenticateToken, async (req, res) => {
    const { code } = req.body || {};
    const preview = req.query.preview === '1';
    if (!code && !req.user.passkey) return res.status(400).json({ error: 'Missing code' });
    try {
      const user = await getUserByUsername(req.user.username);
      if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
      if (code) {
        const valid = await verifyTotp(user, code);
        if (!valid) return res.status(401).json({ error: 'Invalid code' });
      }
      const codes = genCodes();
      if (!preview) {
        await updateBackupCodes(req.user.id, JSON.stringify(codes));
      }
      res.json({ codes });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/totp/check', authenticateToken, async (req, res) => {
    const { code } = req.body || {};
    if (!code && !req.user.passkey) return res.status(400).json({ error: 'Missing code' });
    try {
      const user = await getUserByUsername(req.user.username);
      if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
      if (code) {
        const valid = await verifyTotp(user, code);
        if (!valid) return res.status(401).json({ error: 'Invalid code' });
      }
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
    const { code } = req.body || {};
    if (!code && !req.user.passkey) return res.status(400).json({ error: 'Missing code' });
    try {
      const user = await getUserByUsername(req.user.username);
      if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
      if (code) {
        const valid = await verifyTotp(user, code);
        if (!valid) return res.status(401).json({ error: 'Invalid code' });
      }
      await disableTotp(user.id);
      res.json({ message: 'disabled' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/totp/update', authenticateToken, async (req, res) => {
    const { code } = req.body || {};
    if (!code && !req.user.passkey) return res.status(400).json({ error: 'Missing code' });
    try {
      const user = await getUserByUsername(req.user.username);
      if (!user || !user.totp_secret) return res.status(400).json({ error: 'No totp' });
      if (code) {
        const valid = await verifyTotp(user, code);
        if (!valid) return res.status(401).json({ error: 'Invalid code' });
      }
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
      const existing = await getPasskeysByUser(user.id);
      const options = await generateRegistrationOptions({
        rpName: 'LetuslearnID',
        rpID: req.headers.host.split(':')[0],
        userID: Buffer.from(String(user.id)),
        userName: user.username,
        excludeCredentials: existing.map(k => ({ id: Buffer.from(k.credential_id, 'base64url'), type:'public-key' }))
      });
      challenges[user.username] = options.challenge;
      res.json(options);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/passkey/register', authenticateToken, async (req, res) => {
    const { id, rawId, response, type } = req.body;
    if (!id || !rawId || !response || !type) {
      return res.status(400).json({ error: 'Missing credential data' });
    }
    try {
      const expectedChallenge = challenges[req.user.username];
      if (!expectedChallenge) return res.status(400).json({ error: 'No challenge' });
      const verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: `http://${req.headers.host}`,
        expectedRPID: req.headers.host.split(':')[0],
        requireUserVerification: false
      });
      if (!verification.verified || !verification.registrationInfo) {
        throw new Error('Verification failed');
      }
      const { credential } = verification.registrationInfo;
      await addPasskey(
        req.user.id,
        credential.id,
        Buffer.from(credential.publicKey).toString('base64'),
        credential.counter
      );
      delete challenges[req.user.username];
      res.json({ message: 'registered' });
    } catch (err) {
      console.error('Passkey registration failed:', err.message);
      res.status(400).json({ error: 'Verification failed' });
    }
  });

  app.post('/passkey/auth-options', async (req, res) => {
    const { fingerprint, username } = req.body;
    if (!fingerprint) return res.status(400).json({ error: 'Missing fingerprint' });
    try {
      let sess = await getValidSession(fingerprint);
      let uid, remember;
      if (!sess) {
        const auth = req.headers['authorization'];
        if (!auth) {
          if (!username) return res.status(404).json({ error: 'Not found' });
          const user = await getUserByUsername(username);
          if (!user) return res.status(404).json({ error: 'Not found' });
          uid = user.id;
        } else {
          try {
            const token = auth.split(' ')[1];
            const info = jwt.verify(token, SECRET);
            const user = await getUserByUsername(info.username);
            if (!user || (info.fingerprint && info.fingerprint !== fingerprint)) {
              return res.status(404).json({ error: 'Not found' });
            }
            uid = user.id;
            remember = info.remember;
          } catch (e) {
            return res.status(404).json({ error: 'Not found' });
          }
        }
      } else {
        uid = sess.user_id;
      }
      const keys = await getPasskeysByUser(uid);
      if (!keys.length) return res.status(404).json({ error: 'No passkey' });
      const options = await generateAuthenticationOptions({
        rpID: req.headers.host.split(':')[0],
        allowCredentials: keys.map(k => ({ id: k.credential_id, type: 'public-key' }))
      });
      challenges[fingerprint] = sess ? { challenge: options.challenge, sess } : { challenge: options.challenge, uid, remember };
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
    const { rawId, response } = req.body;
    if (!rawId || !response) {
      return res.status(400).json({ error: 'Missing credential data' });
    }
    try {
      const credId = Buffer.from(rawId, 'base64').toString('base64url');
      const key = await getPasskeyByCredId(credId);
      const uid = data.sess ? data.sess.user_id : data.uid;
      if (!key || key.user_id !== uid) return res.status(404).json({ error: 'Unknown credential' });
      const user = await promisify(db.get.bind(db))('SELECT * FROM users WHERE id = ?', uid);
      const verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: data.challenge,
        expectedOrigin: `http://${req.headers.host}`,
        expectedRPID: req.headers.host.split(':')[0],
        requireUserVerification: false,
        credential: {
          id: key.credential_id,
          publicKey: Buffer.from(key.public_key, 'base64'),
          counter: key.counter
        }
      });
      await updatePasskeyCounter(key.credential_id, verification.authenticationInfo.newCounter);
      const days = data.sess ? Math.max(1, Math.round((data.sess.expires_at - Date.now()) / 86400000)) : (data.remember || 1);
      const token = generateToken(user, days, { passkey: true });
      const sso = await loginToSso(db, user.username);
      delete challenges[fingerprint];
      res.json({ token, sso });
    } catch (err) {
      console.error('Passkey authentication failed:', err.message);
      res.status(400).json({ error: 'Verification failed' });
    }
  });

  app.post('/passkey/remove', authenticateToken, async (req, res) => {
    const { credId } = req.body || {};
    try {
      await removePasskey(req.user.id, credId);
      res.json({ message: 'removed' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/recover', async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Missing username' });
    try {
      const user = await getUserByUsername(username);
      if (!user || !user.email) return res.status(404).json({ error: 'Not found' });
      const { code } = await getOrCreateCode(user.id, req.ip);
      const id = await addPending(username, user.email, null, code, 'recover');
      sendCode(user.email, code, req.ip).catch(() => {});
      res.json({ id });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/recover/verify', async (req, res) => {
    const { id, code } = req.body;
    if (!id || !code) return res.status(400).json({ error: 'Missing data' });
    try {
      const record = await getPending(id);
      if (!record || record.code !== code || record.action !== 'recover') return res.status(400).json({ error: 'Invalid code' });
      const user = await getUserByUsername(record.username);
      if (!user) return res.status(404).json({ error: 'User not found' });
      await removePending(id);
      await promisify(db.run.bind(db))('UPDATE verifycode SET authorized=1 WHERE code=? AND ip=? AND authorized=0', record.code, req.ip);
      const token = generateToken(user, 1);
      res.json({ token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/reset-password', async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Missing username' });
    try {
      const user = await getUserByUsername(username);
      if (!user || !user.email) return res.status(404).json({ error: 'Not found' });
      const { code } = await getOrCreateCode(user.id, req.ip);
      const id = await addPending(username, user.email, null, code, 'reset');
      sendCode(user.email, code, req.ip).catch(() => {});
      res.json({ id });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/reset-password/check', async (req, res) => {
    const { id, code } = req.body;
    if (!id || !code) return res.status(400).json({ error: 'Missing data' });
    try {
      const record = await getPending(id);
      if (!record || record.code !== code || record.action !== 'reset') {
        return res.status(400).json({ error: 'Invalid code' });
      }
      res.json({ message: 'verified' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/reset-password/update', async (req, res) => {
    const { id, code, password } = req.body;
    if (!id || !code || !password) return res.status(400).json({ error: 'Missing data' });
    try {
      const record = await getPending(id);
      if (!record || record.code !== code || record.action !== 'reset') {
        return res.status(400).json({ error: 'Invalid code' });
      }
      const user = await getUserByUsername(record.username);
      if (!user) return res.status(404).json({ error: 'User not found' });
      const hash = await bcrypt.hash(password, 10);
      await updateUserPassword(user.id, hash);
      await removePending(id);
      await promisify(db.run.bind(db))('UPDATE verifycode SET authorized=1 WHERE code=? AND ip=? AND authorized=0', record.code, req.ip);
      res.json({ message: 'updated' });
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
      const sso = await loginToSso(db, user.username);
      res.json({ token, sso });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });
  return { authenticateToken, verifyToken };
}

export default setupUserRoutes;
