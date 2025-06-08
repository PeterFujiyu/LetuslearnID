const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const initOidcConfig = require('./oidcconfig');
const dbFile = process.env.DB_FILE || path.join(__dirname, 'users.db');
const db = new sqlite3.Database(dbFile);
const run = (q,p=[])=>new Promise((res,rej)=>db.run(q,p,err=>err?rej(err):res()));
(async()=>{
  await run('DROP TABLE IF EXISTS oidcauth');
  await initOidcConfig(db,true);
  db.close();
})();
