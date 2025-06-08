import express from 'express';
import Provider, { Interaction, KoaContextWithOIDC } from 'oidc-provider';
import sqlite3 from 'sqlite3';
import {open} from 'sqlite';
import bcrypt from 'bcrypt';

const ISSUER = process.env.OIDC_ISSUER ?? 'https://id.letuslearn.now';
const PORT   = process.env.OIDC_PORT   ?? 4000;

/* --- 1) 复用现有用户库 --------------------------------------- */
const db = await open({filename: './users.db', driver: sqlite3.Database});

async function findAccount(ctx: KoaContextWithOIDC, id: string) {
  const user = await db.get('SELECT id,email,twofa_enabled FROM users WHERE id = ?', id);
  if (!user) return undefined;
  return {
    accountId: id,
    async claims() {
      return {
        sub: id,
        email: user.email,
        email_verified: 1,
        twofa_enabled: !!user.twofa_enabled,
      };
    },
  };
}

/* --- 2) 定义 Provider ---------------------------------------- */
const oidc = new Provider(ISSUER, {
  features: { pkce: { required: () => true } },    // 只开放 Code + PKCE
  async findAccount(ctx, id) { return findAccount(ctx, id); },
  clients: [{
    client_id: 'cloudreve',
    client_secret: process.env.CLOUDREVE_SECRET ?? 'CHANGE_ME',
    redirect_uris: ['https://cloud.example.com/api/sso/letuslearn/callback'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
  }],
  cookies: { keys: [process.env.SESSION_KEY ?? 'dev-session'] },
});

/* --- 3) 把现有登录页接入交互流程 ------------------------------ */
oidc.proxy = true;                       // 让 provider 按 X-Forwarded-* 识别 Scheme
oidc.on('interaction.started', (ctx: Interaction) => {
  // 这里只做日志，可按需把 ctx.params 保存起来
  console.info('OIDC interaction started', ctx.uid);
});

/* --- 4) 与 Express 结合 -------------------------------------- */
const app = express();
app.use('/oidc', oidc.callback());       // 暴露 /.well-known/*
app.listen(PORT, () => console.log(`OIDC up @ ${ISSUER}`));