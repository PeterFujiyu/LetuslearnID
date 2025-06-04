# LetuslearnID

This repository contains a lightweight account system built with Node.js and SQLite.

## Getting Started

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and set values for `JWT_SECRET`, `DB_PATH` and `PORT`.
3. Install dependencies and start the server:
   ```bash
   cd server
   npm install
   node index.js
   ```

The default configuration stores the SQLite database in `server/users.db` and listens on port 3000.
