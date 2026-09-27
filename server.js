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
const ADMIN_UID = process.env.ADMIN_UID;                 // YOUR Google account's UID only. Never in frontend code.
const DATABASE_URL = process.env.DATABASE_URL;
const pool = DATABASE_URL ? new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
}) : null;

if (!GOOGLE_CLIENT_ID || !ADMIN_UID || !DATABASE_URL) {
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
function requireAdmin(req, res, next) {
  if (req.user && req.user.sub === ADMIN_UID) return next();
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
 try{ const u=await upsertUser(req.user); res.json({user:publicUser(u),isAdmin:!!ADMIN_UID&&req.user.sub===ADMIN_UID}); }
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
app.get('/api/is-admin', requireAuth, (req, res) => {
  res.json({ isAdmin: req.user.sub === ADMIN_UID });
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
// value. Admin status is a fixed constant on the server, not stored data
// that any request (including from the admin) can edit.

app.get('*', (req,res) => {
  res.sendFile(require('path').join(__dirname,'public','divide.html'));
});

const port = process.env.PORT || 3000;
async function initDb(){
  if(!pool) return;
    await pool.query("CREATE TABLE IF NOT EXISTS users (google_sub TEXT PRIMARY KEY,email TEXT NOT NULL,name TEXT,picture TEXT,coins INTEGER NOT NULL DEFAULT 20,wins INTEGER NOT NULL DEFAULT 0,games INTEGER NOT NULL DEFAULT 0,collected INTEGER NOT NULL DEFAULT 0,owned_themes JSONB NOT NULL DEFAULT '[\"classic\"]'::jsonb,equipped_theme TEXT NOT NULL DEFAULT 'classic',revision BIGINT NOT NULL DEFAULT 0,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
}
initDb().then(()=>app.listen(port,()=>console.log('Divide server running on :'+port))).catch(e=>{console.error(e);process.exit(1);});
