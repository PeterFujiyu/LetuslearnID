const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { promisify } = require('util');

const app = express();
app.use(express.json());

const dbFile = process.env.DB_FILE || path.join(__dirname, 'users.db');
const db = new sqlite3.Database(dbFile);


// Initialize user table if it doesn't exist
const initDb = () => {
  const query = `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )`;
  return promisify(db.run.bind(db))(query);
};

const getUserByUsername = async (username) => {
  const query = 'SELECT * FROM users WHERE username = ?';
  return promisify(db.get.bind(db))(query, username);
};

const createUser = async (username, passwordHash) => {
  const query = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
  return promisify(db.run.bind(db))(query, username, passwordHash);
};

// JWT secret; in production use environment variable
const SECRET = process.env.JWT_SECRET || 'dev-secret';

const generateToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '1h' });
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
  const { username, password } = req.body;
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
    const token = generateToken(user);
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


initDb().then(() => {
  if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  }
}).catch((err) => {
  console.error('Failed to initialize database', err);
});

module.exports = { app, initDb, db };
