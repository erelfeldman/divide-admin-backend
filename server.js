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

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;   // from Google Cloud Console
const ADMIN_UID = process.env.ADMIN_UID;                 // YOUR Google account's UID only. Never in frontend code.

if (!GOOGLE_CLIENT_ID || !ADMIN_UID) {
  throw new Error('Set GOOGLE_CLIENT_ID and ADMIN_UID as server environment variables (never hardcode in a file you commit or ship to the browser).');
}

const client = new OAuth2Client(GOOGLE_CLIENT_ID);
const app = express();
app.use(express.json());

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
app.get('/api/is-admin', requireAuth, (req, res) => {
  res.json({ isAdmin: req.user.sub === ADMIN_UID });
});

// Example protected admin action. Every admin route MUST use both
// requireAuth and requireAdmin — never trust a client-supplied "role" field.
app.post('/api/admin/reset-user-coins', requireAuth, requireAdmin, (req, res) => {
  // ... perform the privileged action here ...
  res.json({ ok: true });
});

// There is intentionally NO endpoint anywhere that can change ADMIN_UID,
// promote another account, or accept a client-supplied "isAdmin"/"role"
// value. Admin status is a fixed constant on the server, not stored data
// that any request (including from the admin) can edit.

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Admin-check server running on :' + port));
