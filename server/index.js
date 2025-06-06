const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { promisify } = require('util');

const app = express();
app.use(express.json());
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
    password_hash TEXT
  )`;
  const sessionQuery = `CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    fingerprint TEXT,
    expires_at INTEGER
  )`;
  return Promise.all([
    promisify(db.run.bind(db))(query),
    promisify(db.run.bind(db))(sessionQuery)
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

const updateUserPassword = async (id, passwordHash) => {
  const query = 'UPDATE users SET password_hash = ? WHERE id = ?';
  return promisify(db.run.bind(db))(query, passwordHash, id);
};

// JWT secret; in production use environment variable
const SECRET = process.env.JWT_SECRET || 'dev-secret';

const generateToken = (user, days) => {
  const opts = days && days > 1 && days < 14 ? { expiresIn: `${days}d` } : { expiresIn: '1h' };
  return jwt.sign({ id: user.id, username: user.username }, SECRET, opts);
};

const authenticateToken = (req, res, next) => {
  const auth = req.headers['authorization'];
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
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
    res.json({ id: user.id, username: user.username });
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
