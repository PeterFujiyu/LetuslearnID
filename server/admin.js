const { promisify } = require('util');

module.exports = function(app, db, auth){
  const isAdmin = async id => {
    const row = await promisify(db.get.bind(db))(
      'SELECT 1 FROM user_groups ug JOIN groups g ON ug.group_id=g.id WHERE ug.user_id=? AND g.name="admin"',
      id
    );
    return !!row;
  };
  const adminAuth = [auth, async (req,res,next)=>{
    const ok = await isAdmin(req.user.id);
    if(!ok) return res.status(403).json({error:'forbidden'});
    next();
  }];

  app.get('/admin/users', adminAuth, async (req,res)=>{
    const list = await promisify(db.all.bind(db))('SELECT id,username,email FROM users');
    res.json(list);
  });
  app.post('/admin/users', adminAuth, async (req,res)=>{
    const {username,email,password} = req.body;
    if(!username||!password) return res.status(400).json({error:'missing data'});
    try{
      const hash = require('bcryptjs').hashSync(password,10);
      const stmt = await promisify(db.run.bind(db))('INSERT INTO users (username,email,password_hash) VALUES (?,?,?)',username,email,hash);
      await promisify(db.run.bind(db))('INSERT INTO user_groups (user_id,group_id) VALUES (?,2)', stmt.lastID);
      res.json({id:stmt.lastID});
    }catch(err){
      res.status(400).json({error:'failed'});
    }
  });
  app.delete('/admin/users/:id', adminAuth, async (req,res)=>{
    await promisify(db.run.bind(db))('DELETE FROM users WHERE id=?', req.params.id);
    await promisify(db.run.bind(db))('DELETE FROM user_groups WHERE user_id=?', req.params.id);
    res.json({message:'deleted'});
  });

  app.get('/admin/users/:id', adminAuth, async (req,res)=>{
    const uid = req.params.id;
    const user = await promisify(db.get.bind(db))('SELECT id,username,email,totp_secret FROM users WHERE id=?', uid);
    if(!user) return res.status(404).json({error:'not found'});
    const groups = await promisify(db.all.bind(db))('SELECT group_id FROM user_groups WHERE user_id=?', uid);
    const passkey = await promisify(db.get.bind(db))('SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1', uid);
    res.json({
      id:user.id,
      username:user.username,
      email:user.email,
      totp:!!user.totp_secret,
      passkey:!!passkey,
      groups:groups.map(g=>g.group_id)
    });
  });

  app.put('/admin/users/:id', adminAuth, async (req,res)=>{
    const uid = req.params.id;
    const {password,totpEnabled,passkeyEnabled,groups=[]} = req.body;
    if(password){
      const hash = require('bcryptjs').hashSync(password,10);
      await promisify(db.run.bind(db))('UPDATE users SET password_hash=? WHERE id=?', hash, uid);
    }
    if(totpEnabled===false){
      await promisify(db.run.bind(db))('UPDATE users SET totp_secret=NULL, backup_codes=NULL WHERE id=?', uid);
    }
    if(passkeyEnabled===false){
      await promisify(db.run.bind(db))('DELETE FROM passkeys WHERE user_id=?', uid);
    }
    if(Array.isArray(groups)){
      await promisify(db.run.bind(db))('DELETE FROM user_groups WHERE user_id=?', uid);
      for(const gid of groups){
        await promisify(db.run.bind(db))('INSERT OR IGNORE INTO user_groups (user_id,group_id) VALUES (?,?)', uid, gid);
      }
    }
    res.json({message:'updated'});
  });

  app.get('/admin/users/:id/code', adminAuth, async (req,res)=>{
    const uid = req.params.id;
    const exist = await promisify(db.get.bind(db))(
      'SELECT code FROM verifycode WHERE user_id=? AND authorized=0 AND expires_at>? ORDER BY id DESC LIMIT 1',
      uid,
      Date.now()
    );
    if(exist){
      return res.json({code:exist.code});
    }
    const code = Math.floor(100000+Math.random()*900000).toString();
    await promisify(db.run.bind(db))(
      'INSERT INTO verifycode (user_id, ip, code, expires_at) VALUES (?,?,?,?)',
      uid,
      req.ip,
      code,
      Date.now()+600000
    );
    res.json({code});
  });

  app.get('/admin/groups', adminAuth, async (req,res)=>{
    const gs = await promisify(db.all.bind(db))('SELECT * FROM groups');
    res.json(gs);
  });
  app.post('/admin/groups', adminAuth, async (req,res)=>{
    const {name,parent_id,permissions} = req.body;
    if(!name) return res.status(400).json({error:'missing name'});
    const stmt = await promisify(db.run.bind(db))(
      'INSERT INTO groups (name,parent_id,permissions) VALUES (?,?,?)',
      name,
      parent_id||null,
      permissions||null
    );
    res.json({id:stmt.lastID});
  });
  app.put('/admin/groups/:id', adminAuth, async (req,res)=>{
    const {name,parent_id,permissions} = req.body;
    await promisify(db.run.bind(db))(
      'UPDATE groups SET name=?, parent_id=?, permissions=? WHERE id=?',
      name,
      parent_id||null,
      permissions||null,
      req.params.id
    );
    res.json({message:'updated'});
  });
  app.delete('/admin/groups/:id', adminAuth, async (req,res)=>{
    await promisify(db.run.bind(db))('DELETE FROM groups WHERE id=?', req.params.id);
    await promisify(db.run.bind(db))('DELETE FROM user_groups WHERE group_id=?', req.params.id);
    res.json({message:'deleted'});
  });

  app.post('/admin/user-groups', adminAuth, async (req,res)=>{
    const {user_id,group_id} = req.body;
    if(!user_id||!group_id) return res.status(400).json({error:'missing'});
    await promisify(db.run.bind(db))('INSERT OR IGNORE INTO user_groups (user_id,group_id) VALUES (?,?)',user_id,group_id);
    res.json({message:'added'});
  });
  app.delete('/admin/user-groups', adminAuth, async (req,res)=>{
    const {user_id,group_id} = req.body;
    await promisify(db.run.bind(db))('DELETE FROM user_groups WHERE user_id=? AND group_id=?', user_id, group_id);
    res.json({message:'removed'});
  });

  app.post('/admin/sql', adminAuth, async (req,res)=>{
    const {sql,args=[]} = req.body;
    if(!sql) return res.status(400).json({error:'missing sql'});
    try{
      if(sql.trim() === '.tables'){
        const tbs = await promisify(db.all.bind(db))(
          "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        );
        return res.json({rows:tbs.map(t=>t.name)});
      }
      const rows = await promisify(db.all.bind(db))(sql, args);
      res.json({rows});
    }catch(err){
      res.status(400).json({error:'bad sql'});
    }
  });
};
