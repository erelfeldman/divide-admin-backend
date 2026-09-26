# Single-Admin backend — setup

This is the minimum needed for a security claim like "only my Google account
is Admin, and nothing on the frontend can change that" to actually be true.
It **cannot** be added to the `divide.html` artifact itself — that file has
no server, no secrets, and no database; anything placed only in it can be
edited by anyone in their browser's dev tools.

## 1. Get a Google OAuth Client ID
In [Google Cloud Console](https://console.cloud.google.com) → APIs & Services
→ Credentials → Create OAuth 2.0 Client ID (type: Web application). Add your
site's domain to "Authorized JavaScript origins". Copy the Client ID.

## 2. Find your own UID (once)
Sign in on your site with Google Identity Services, send the resulting ID
token to a temporary `/api/is-admin`-style route, and log `payload.sub` on
the server. That string is your permanent Google UID. Copy it — do not
guess it or use your email (emails can change; `sub` cannot).

## 3. Set environment variables on your host (never in client code)
```
GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com
ADMIN_UID=the-sub-value-from-step-2
```

## 4. Deploy `server.js`
Any Node host works (Render, Railway, Fly.io, Cloud Run, a VPS). Run:
```
npm install
npm start
```

## 5. Wire up the frontend
- On login, get the Google ID token (via Google Identity Services' JS SDK).
- Send it as `Authorization: Bearer <idToken>` on every request, including
  `/api/is-admin` (to decide whether to *show* the Admin Panel button) and
  every `/api/admin/*` action (which the server re-checks independently).
- Showing/hiding the button is cosmetic. The real protection is that
  every admin route runs `requireAuth` + `requireAdmin` on the server,
  which re-verifies the token's signature with Google and compares the
  UID — a value that never reaches the browser and can't be edited there.

## What this guarantees
- A normal user, another Google account, or a guest: `req.user.sub` never
  equals `ADMIN_UID`, so every admin route returns 403, regardless of what
  they change in the browser, localStorage, or the URL.
- There is no endpoint that sets or promotes admin status — it's a fixed
  server constant, not stored/editable data.
