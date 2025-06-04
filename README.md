# LetuslearnID

This repository contains a lightweight account management server built with [Express](https://expressjs.com/). It currently stores user data in SQLite to keep resource usage minimal.

## Prerequisites

- **Node.js** 18 or 20
- **npm** (comes with Node.js)
- **Optional:** Python 3.11 if `node-gyp` needs to compile native modules

## Setup

Install dependencies by running:

```bash
cd server && npm install
```

## Running the Server

Before starting the server you can set the following environment variables:

- `JWT_SECRET` – secret used to sign tokens (default: `dev-secret`)
- `PORT` – port for the HTTP server (default: `3000`)
- `DB_PATH` – path to the SQLite database file (default: `./server/users.db`)

Start the API from the `server` directory with:

```bash
node index.js
```

Or run the convenience script:

```bash
npm start
```
Once running, visit http://localhost:3000/ to see the web interface.

## Future Work

The project plans to migrate from SQLite to PostgreSQL in order to scale more efficiently. This migration is tracked as future technical debt.
