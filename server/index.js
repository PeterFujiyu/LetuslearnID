import express from 'express';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { initDb, db, get } from './lib/db.js';
export { initDb, db } from './lib/db.js';
import { initOIDCProvider } from './provider.js';
import userRoutes from './users.js';
import adminRoutes from './admin.js';
import initOidcConfig from './oidcconfig.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const app = express();
app.set('trust proxy', true);
app.use(express.json());

const clientDir = path.join(__dirname, '..', 'client');
app.use(express.static(clientDir));
app.use('/i18n', express.static(path.join(__dirname, '..', 'i18n')));
app.get('/', (req, res) => {
  res.sendFile(path.join(clientDir, 'index', 'index.html'));
});

const userMod = userRoutes(app, db);
adminRoutes(app, db, userMod.authenticateToken);

app.use('/admin', async (req, res, next) => {
  let token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token && req.query.t) token = req.query.t;
  try {
    const user = await userMod.verifyToken(token);
    const row = await get("SELECT 1 FROM user_groups ug JOIN groups g ON ug.group_id=g.id WHERE ug.user_id=? AND g.name='admin'", user.id);
    if (!row) return res.status(403).send('Forbidden');
    express.static(path.join(clientDir, 'admin'))(req, res, next);
  } catch (err) {
    res.status(401).send('Unauthorized');
  }
});

export let oidc;
export async function initOIDC() {
  await initOidcConfig(db);
  let issuer = process.env.ISSUER || 'https://id.letuslearn.now';
  if (!issuer.startsWith('http')) issuer = 'https://' + issuer;
  oidc = await initOIDCProvider(issuer);
  app.use(oidc.callback());
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const PORT = process.env.PORT || 3000;
  initDb().then(initOIDC).then(() => {
    app.listen(PORT, () => {
      console.log(`OIDC Provider listening at ${process.env.ISSUER || 'https://id.letuslearn.now'} (local:${PORT})`);
    });
  }).catch(err => {
    console.error('Failed to start', err);
  });
}
