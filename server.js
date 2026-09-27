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
  throw new Error('Set GOOGLE_CLIENT_ID, ADMIN_UID and DATABASE_URL as server environment variables (never hardcode secrets in a file you commit or ship to the browser).');
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
 const r=await pool.query('INSERT INTO users (google_sub,email,name,picture) VALUES ($1,$2,$3,$4) ON CONFLICT (google_sub) DO UPDATE SET email=EXCLUDED.email,name=EXCLUDED.name,picture=EXCLUDED.picture,updated_at=NOW() RETURNING *',[p.sub,p.email||'',p.name||null,p.picture||null]);
 return r.rows[0];
}
app.post('/api/auth/sync', requireAuth, async (req,res)=>{
 try{ const u=await upsertUser(req.user); res.json({user:publicUser(u),isAdmin:isAdminUser(req.user)}); }
 catch(e){console.error(e);res.status(500).json({error:'database error'});}
});
app.get('/api/me', requireAuth, async (req,res)=>{
 try{ const u=await upsertUser(req.user); res.json({user:publicUser(u),isAdmin:!!ADMIN_UID&&req.user.sub===ADMIN_UID}); }
 catch(e){console.error(e);res.status(500).json({error:'database error'});}
});
app.post('/api/save', requireAuth, async (req,res)=>{
 try{
  const d=req.body||{};
  const nums=['coins','wins','games','collected'];
  const v=nums.map(k=>Math.max(0,Math.floor(Number(d[k]??0))));
  const themes=Array.isArray(d.ownedThemes)?d.ownedThemes.slice(0,50):['classic'];
  const equipped=typeof d.equippedTheme==='string'?d.equippedTheme.slice(0,50):'classic';
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
  res.json({comment:r.rows[0]});
 }catch(e){res.status(400).json({error:'invalid post'});}
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
}
initDb().then(()=>app.listen(port,()=>console.log('Divide server running on :'+port))).catch(e=>{console.error(e);process.exit(1);});
