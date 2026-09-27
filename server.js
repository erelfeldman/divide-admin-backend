/**
 * Reference backend for a SINGLE hardcoded Admin, enforced server-side.
 * This is the only place "who is Admin" is decided. The frontend never
 * decides this — it only shows/hides UI based on what THIS server says,
 * and every admin action is re-checked here again before it runs.
 *
 * Deploy this yourself (Render / Railway / Fly.io / Cloud Run / a VPS /
 * a serverless function). It cannot run inside a published chat artifact,
 * which has no server and no secret storage.
 */
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const { Pool } = require('pg');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;   // from Google Cloud Console
const ADMIN_UID = process.env.ADMIN_UID || '';                 // Legacy single-admin UID (optional). Never in frontend code.
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
const DATABASE_URL = process.env.DATABASE_URL;
const pool = DATABASE_URL ? new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
}) : null;

if (!GOOGLE_CLIENT_ID || (!ADMIN_UID && ADMIN_EMAILS.length === 0) || !DATABASE_URL) {
  throw new Error('Set GOOGLE_CLIENT_ID, ADMIN_EMAILS (or legacy ADMIN_UID) and DATABASE_URL as server environment variables.');
}

const client = new OAuth2Client(GOOGLE_CLIENT_ID);
const app = express();
app.use(express.json({ limit: '256kb' }));
app.use(require('express').static(require('path').join(__dirname, 'public')));

/**
 * Verifies the Google ID token's signature and issuer with Google itself
 * (not just decoding it) and returns the token's payload. `payload.sub`
 * is Google's permanent, non-spoofable unique ID for that account.
 */
async function verifyGoogleToken(idToken) {
  const ticket = await client.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
  return ticket.getPayload(); // { sub, email, name, picture, ... }
}

/** Attaches req.user for any authenticated request. */
async function requireAuth(req, res, next) {
  try {
    const idToken = (req.headers.authorization || '').replace('Bearer ', '');
    if (!idToken) return res.status(401).json({ error: 'no token' });
    req.user = await verifyGoogleToken(idToken);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

/** Only passes if the verified UID matches the one single admin UID. */
function isAdminUser(user){
  const email = String(user?.email || '').toLowerCase();
  return !!user && ((ADMIN_UID && user.sub === ADMIN_UID) || ADMIN_EMAILS.includes(email));
}
function requireAdmin(req, res, next) {
  if (isAdminUser(req.user)) return next();
  return res.status(403).json({ error: 'not admin' });
}

// Any logged-in user can ask "am I admin?" — the frontend uses this only
// to decide whether to SHOW the Admin Panel button. Hiding it is cosmetic;
// requireAdmin on the real endpoints below is what actually enforces it.
app.get('/api/health', async (req, res) => {
  try {
    if (!pool) return res.status(503).json({ ok: false, database: false, googleAuth: !!GOOGLE_CLIENT_ID });
    await pool.query('SELECT 1');
    res.json({ ok: true, database: true, googleAuth: !!GOOGLE_CLIENT_ID });
  } catch { res.status(503).json({ ok: false, database: false, googleAuth: !!GOOGLE_CLIENT_ID }); }
});

app.get('/api/config', (req, res) => {
  res.json({ googleClientId: GOOGLE_CLIENT_ID || null });
});

function publicUser(u){
 return {google_sub:u.google_sub,email:u.email,name:u.name,picture:u.picture,coins:u.coins,wins:u.wins,games:u.games,collected:u.collected,ownedThemes:u.owned_themes,equipped:u.equipped_theme,revision:Number(u.revision)};
}
async function upsertUser(p){
 const r=await pool.query('INSERT INTO users (google_sub,email,name,picture,coins) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (google_sub) DO UPDATE SET email=EXCLUDED.email,name=EXCLUDED.name,picture=EXCLUDED.picture,updated_at=NOW() RETURNING *',[p.sub,p.email||'',p.name||null,p.picture||null,isAdminUser(p)?2147483647:20]);
 return r.rows[0];
}
app.post('/api/auth/sync', requireAuth, async (req,res)=>{
 try{ const u=await upsertUser(req.user); res.json({user:publicUser(u),isAdmin:isAdminUser(req.user)}); }
 catch(e){console.error(e);res.status(500).json({error:'database error'});}
});
app.get('/api/me', requireAuth, async (req,res)=>{
 try{ const u=await upsertUser(req.user); res.json({user:publicUser(u),isAdmin:isAdminUser(req.user)}); }
 catch(e){console.error(e);res.status(500).json({error:'database error'});}
});
app.post('/api/save', requireAuth, async (req,res)=>{
 try{
  const d=req.body||{};
  const nums=['coins','wins','games','collected'];
  const v=nums.map(k=>Math.max(0,Math.floor(Number(d[k]??0))));
  const themes=Array.isArray(d.ownedThemes)?d.ownedThemes.slice(0,50):['classic'];
  const equipped=typeof d.equippedTheme==='string'?d.equippedTheme.slice(0,50):'classic';
  const isAdmin=isAdminUser(req.user); if(isAdmin)v[0]=2147483647;
  const r=await pool.query('UPDATE users SET coins=$2,wins=$3,games=$4,collected=$5,owned_themes=$6,equipped_theme=$7,revision=revision+1,updated_at=NOW() WHERE google_sub=$1 RETURNING *',[req.user.sub,...v,JSON.stringify(themes),equipped]);
  if(!r.rowCount){const n=await upsertUser(req.user);return res.json({user:publicUser(n)});}
  res.json({user:publicUser(r.rows[0])});
 }catch(e){console.error(e);res.status(400).json({error:'invalid save data'});}
});
app.get('/api/admin/users', requireAuth, requireAdmin, async (req,res)=>{
 try{const r=await pool.query('SELECT google_sub,email,name,coins,wins,games,collected,updated_at,revision FROM users ORDER BY updated_at DESC LIMIT 200');res.json({users:r.rows});}
 catch(e){console.error(e);res.status(500).json({error:'database error'});}
});
app.get('/api/social/feed', requireAuth, async (req,res)=>{
 try{
  const r=await pool.query(`SELECT p.id,p.body,p.created_at,u.name,u.email,u.picture,
   (SELECT COUNT(*) FROM social_likes l WHERE l.post_id=p.id)::int AS likes,
   (SELECT COUNT(*) FROM social_comments c WHERE c.post_id=p.id)::int AS comments
   FROM social_posts p JOIN users u ON u.google_sub=p.google_sub
   ORDER BY p.created_at DESC LIMIT 50`);
  res.json({posts:r.rows});
 }catch(e){console.error(e);res.status(500).json({error:'database error'});}
});
app.post('/api/social/posts', requireAuth, async (req,res)=>{
 const body=String(req.body?.body||'').trim().slice(0,500);
 if(!body)return res.status(400).json({error:'empty post'});
 try{
  const r=await pool.query('INSERT INTO social_posts (google_sub,body) VALUES ($1,$2) RETURNING id,body,created_at',[req.user.sub,body]);
  res.json({post:r.rows[0]});
 }catch(e){console.error(e);res.status(500).json({error:'database error'});}
});
app.post('/api/social/posts/:id/like', requireAuth, async (req,res)=>{
 try{
  await pool.query('INSERT INTO social_likes (post_id,google_sub) VALUES ($1,$2) ON CONFLICT DO NOTHING',[req.params.id,req.user.sub]);
  const owner=(await pool.query('SELECT google_sub FROM social_posts WHERE id=$1',[req.params.id])).rows[0]?.google_sub;
  if(owner && owner!==req.user.sub) await pool.query('INSERT INTO social_notifications (google_sub,type,text) VALUES ($1,$2,$3)',[owner,'like',`${req.user.email||'שחקן'} עשה/תה לייק לפוסט שלך`]);
  const r=await pool.query('SELECT COUNT(*)::int AS likes FROM social_likes WHERE post_id=$1',[req.params.id]);
  res.json({likes:r.rows[0].likes});
 }catch(e){res.status(400).json({error:'invalid post'});}
});
app.get('/api/social/posts/:id/comments', requireAuth, async (req,res)=>{
 try{
  const r=await pool.query(`SELECT c.id,c.body,c.created_at,u.name,u.email FROM social_comments c
   JOIN users u ON u.google_sub=c.google_sub WHERE c.post_id=$1 ORDER BY c.created_at ASC LIMIT 100`,[req.params.id]);
  res.json({comments:r.rows});
 }catch(e){res.status(400).json({error:'invalid post'});}
});
app.post('/api/social/posts/:id/comments', requireAuth, async (req,res)=>{
 const body=String(req.body?.body||'').trim().slice(0,300);
 if(!body)return res.status(400).json({error:'empty comment'});
 try{
  const r=await pool.query('INSERT INTO social_comments (post_id,google_sub,body) VALUES ($1,$2,$3) RETURNING id,body,created_at',[req.params.id,req.user.sub,body]);
  const owner=(await pool.query('SELECT google_sub FROM social_posts WHERE id=$1',[req.params.id])).rows[0]?.google_sub;
  if(owner && owner!==req.user.sub) await pool.query('INSERT INTO social_notifications (google_sub,type,text) VALUES ($1,$2,$3)',[owner,'comment',`${req.user.email||'שחקן'} הגיב/ה לפוסט שלך`]);
  res.json({comment:r.rows[0]});
 }catch(e){res.status(400).json({error:'invalid post'});}
});
app.get('/api/social/leaderboard', requireAuth, async (req,res)=>{
 try{const r=await pool.query('SELECT name,email,picture,wins,games,collected,coins FROM users ORDER BY wins DESC,collected DESC LIMIT 50');res.json({users:r.rows});}
 catch(e){res.status(500).json({error:'database error'});}
});
app.get('/api/social/players', requireAuth, async (req,res)=>{
 const q=String(req.query.q||'').trim().slice(0,80);
 try{const r=await pool.query("SELECT google_sub,name,email,picture,wins,games,collected FROM users WHERE google_sub<>$1 AND ($2='' OR name ILIKE '%'||$2||'%' OR email ILIKE '%'||$2||'%') ORDER BY name NULLS LAST LIMIT 30",[req.user.sub,q]);res.json({players:r.rows});}
 catch(e){res.status(500).json({error:'database error'});}
});
app.post('/api/social/follow/:sub', requireAuth, async (req,res)=>{
 if(req.params.sub===req.user.sub)return res.status(400).json({error:'cannot follow yourself'});
 try{const r=await pool.query('INSERT INTO social_follows (follower_sub,followed_sub) VALUES ($1,$2) ON CONFLICT DO NOTHING RETURNING follower_sub',[req.user.sub,req.params.sub]);if(!r.rowCount){await pool.query('DELETE FROM social_follows WHERE follower_sub=$1 AND followed_sub=$2',[req.user.sub,req.params.sub]);return res.json({following:false});}
  await pool.query('INSERT INTO social_notifications (google_sub,type,text) VALUES ($1,$2,$3)',[req.params.sub,'follow',`${req.user.email||'שחקן'} התחיל/ה לעקוב אחריך`]);res.json({following:true});}
 catch(e){res.status(400).json({error:'player not found'});}
});
app.get('/api/social/profile/:sub', requireAuth, async (req,res)=>{
 try{
  const user=(await pool.query('SELECT google_sub,name,email,picture,coins,wins,games,collected,owned_themes,equipped_theme FROM users WHERE google_sub=$1',[req.params.sub])).rows[0];
  if(!user)return res.status(404).json({error:'player not found'});
  const counts=await pool.query('SELECT (SELECT COUNT(*) FROM social_follows WHERE followed_sub=$1)::int AS followers,(SELECT COUNT(*) FROM social_follows WHERE follower_sub=$1)::int AS following',[req.params.sub]);
  const follows=await pool.query('SELECT 1 FROM social_follows WHERE follower_sub=$1 AND followed_sub=$2',[req.user.sub,req.params.sub]);
  res.json({profile:{...user,followers:counts.rows[0].followers,following:counts.rows[0].following,isFollowing:!!follows.rowCount,isSelf:req.user.sub===req.params.sub}});
 }catch(e){res.status(500).json({error:'database error'});}
});
app.get('/api/social/achievements', requireAuth, async (req,res)=>{
 const defs=[
  {id:'first_win',name:'First Win',icon:'🥇',text:'ניצחון ראשון'},
  {id:'five_wins',name:'Rising Star',icon:'⭐',text:'5 ניצחונות'},
  {id:'ten_wins',name:'Champion',icon:'🏆',text:'10 ניצחונות'},
  {id:'collector',name:'Collector',icon:'🃏',text:'100 קלפים שנצברו'},
  {id:'social',name:'Social Butterfly',icon:'🌐',text:'פרסום פוסט ראשון'}
 ];
 try{
  const u=(await pool.query('SELECT wins,collected FROM users WHERE google_sub=$1',[req.user.sub])).rows[0]||{};
  const earned=(await pool.query('SELECT achievement_id,earned_at FROM user_achievements WHERE google_sub=$1',[req.user.sub])).rows;
  const have=new Set(earned.map(x=>x.achievement_id)); const conditions={first_win:(u.wins||0)>=1,five_wins:(u.wins||0)>=5,ten_wins:(u.wins||0)>=10,collector:(u.collected||0)>=100};
  if(conditions.first_win||conditions.five_wins||conditions.ten_wins||conditions.collector){for(const id of Object.keys(conditions)){if(conditions[id]&&!have.has(id)){await pool.query('INSERT INTO user_achievements (google_sub,achievement_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',[req.user.sub,id]);have.add(id);}}}
  const postCount=(await pool.query('SELECT COUNT(*)::int n FROM social_posts WHERE google_sub=$1',[req.user.sub])).rows[0].n;if(postCount>=1&&!have.has('social')){await pool.query('INSERT INTO user_achievements (google_sub,achievement_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',[req.user.sub,'social']);have.add('social');}
  res.json({achievements:defs.map(x=>({...x,earned:have.has(x.id),earnedAt:earned.find(e=>e.achievement_id===x.id)?.earned_at||null}))});
 }catch(e){res.status(500).json({error:'database error'});}
});
app.get('/api/social/notifications', requireAuth, async (req,res)=>{
 try{
  const r=await pool.query(`SELECT n.id,n.type,n.text,n.created_at,n.read_at FROM social_notifications n
   WHERE n.google_sub=$1 ORDER BY n.created_at DESC LIMIT 50`,[req.user.sub]);
  res.json({notifications:r.rows});
 }catch(e){res.status(500).json({error:'database error'});}
});
app.post('/api/social/notifications/:id/read', requireAuth, async (req,res)=>{
 try{await pool.query('UPDATE social_notifications SET read_at=NOW() WHERE id=$1 AND google_sub=$2',[req.params.id,req.user.sub]);res.json({ok:true});}
 catch(e){res.status(400).json({error:'invalid notification'});}
});
app.post('/api/social/share-result', requireAuth, async (req,res)=>{
 const text=String(req.body?.text||'').trim().slice(0,500);
 if(!text)return res.status(400).json({error:'empty result'});
 try{
  const r=await pool.query('INSERT INTO social_posts (google_sub,body) VALUES ($1,$2) RETURNING id,body,created_at',[req.user.sub,'🎉 '+text]);
  res.json({post:r.rows[0]});
 }catch(e){res.status(500).json({error:'database error'});}
});
app.get('/api/is-admin', requireAuth, (req, res) => {
  res.json({ isAdmin: isAdminUser(req.user) });
});

// Example protected admin action. Every admin route MUST use both
// requireAuth and requireAdmin — never trust a client-supplied "role" field.
app.post('/api/admin/reset-user-coins', requireAuth, requireAdmin, async (req, res) => {
  const googleSub = String(req.body?.googleSub || '');
  if (!googleSub) return res.status(400).json({ error: 'googleSub required' });
  if (!pool) return res.status(503).json({ error: 'database not configured' });
  try {
    const result = await pool.query('UPDATE users SET coins=0,revision=revision+1,updated_at=NOW() WHERE google_sub=$1 RETURNING *', [googleSub]);
    if (!result.rowCount) return res.status(404).json({ error: 'user not found' });
    const u=result.rows[0];
    res.json({ ok:true, user:{google_sub:u.google_sub,email:u.email,name:u.name,coins:u.coins,wins:u.wins,games:u.games,collected:u.collected,ownedThemes:u.owned_themes,equipped:u.equipped_theme,revision:Number(u.revision)} });
  } catch(e) { console.error(e); res.status(500).json({ error:'database error' }); }
});

// There is intentionally NO endpoint anywhere that can change ADMIN_UID,
// promote another account, or accept a client-supplied "isAdmin"/"role"
// value. Admin status is a fixed server-side allowlist, not stored data
// that any request (including from the admin) can edit.

app.get('*', (req,res) => {
  res.sendFile(require('path').join(__dirname,'public','divide.html'));
});

const port = process.env.PORT || 3000;
async function initDb(){
  if(!pool) return;
    await pool.query("CREATE TABLE IF NOT EXISTS users (google_sub TEXT PRIMARY KEY,email TEXT NOT NULL,name TEXT,picture TEXT,coins INTEGER NOT NULL DEFAULT 20,wins INTEGER NOT NULL DEFAULT 0,games INTEGER NOT NULL DEFAULT 0,collected INTEGER NOT NULL DEFAULT 0,owned_themes JSONB NOT NULL DEFAULT '[\"classic\"]'::jsonb,equipped_theme TEXT NOT NULL DEFAULT 'classic',revision BIGINT NOT NULL DEFAULT 0,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  await pool.query("CREATE TABLE IF NOT EXISTS social_posts (id BIGSERIAL PRIMARY KEY,google_sub TEXT NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 500),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  await pool.query("CREATE TABLE IF NOT EXISTS social_likes (post_id BIGINT NOT NULL REFERENCES social_posts(id) ON DELETE CASCADE,google_sub TEXT NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(post_id,google_sub))");
  await pool.query("CREATE TABLE IF NOT EXISTS social_comments (id BIGSERIAL PRIMARY KEY,post_id BIGINT NOT NULL REFERENCES social_posts(id) ON DELETE CASCADE,google_sub TEXT NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 300),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  await pool.query("CREATE TABLE IF NOT EXISTS social_notifications (id BIGSERIAL PRIMARY KEY,google_sub TEXT NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,type TEXT NOT NULL,text TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),read_at TIMESTAMPTZ)");
  await pool.query("CREATE TABLE IF NOT EXISTS user_achievements (google_sub TEXT NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,achievement_id TEXT NOT NULL,earned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(google_sub,achievement_id))");
  await pool.query("CREATE TABLE IF NOT EXISTS social_follows (follower_sub TEXT NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,followed_sub TEXT NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(follower_sub,followed_sub),CHECK (follower_sub<>followed_sub))");
}
initDb().then(()=>app.listen(port,()=>console.log('Divide server running on :'+port))).catch(e=>{console.error(e);process.exit(1);});
