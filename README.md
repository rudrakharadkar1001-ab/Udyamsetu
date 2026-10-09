# UdyamSetu

Scheme finder website with a real backend: user accounts (register / login / logout) and saved schemes + document checklist that follow the user across devices.

```
public/index.html            the website
netlify/functions/api.mjs    the backend (Netlify Function, path /api/*)
netlify.toml                 Netlify settings
package.json                 backend dependency (@netlify/blobs = storage)
```

Without logging in, the site works exactly as before (data stays in the browser). After login, saved schemes and checklist progress are stored on the server.

## Deploy (GitHub -> Netlify)

1. Put all these files in a GitHub repository (keep the folder structure) and push.
2. On Netlify: **Add new site -> Import an existing project -> GitHub**, choose the repo. Netlify reads `netlify.toml`, so no build settings are needed.
3. **Before using login**, add an environment variable in
   *Site configuration -> Environment variables*:
   - Key: `SESSION_SECRET`
   - Value: a long random string (32+ characters). Generate one with `openssl rand -hex 32`, or any password generator.
   - Mark it as a secret. **Never put this value in GitHub.**
4. Trigger a deploy (Deploys -> Trigger deploy). Open `https://YOUR-SITE.netlify.app/api/health`; it should show `{"ok":true,"configured":true}`.
5. Open the site, click Register, create an account, save a scheme, log in from another device to check it syncs.

## Run locally (optional)

```
npm install
npx netlify dev
```
Create a `.env` file (already git-ignored) containing `SESSION_SECRET=<32+ random characters>`.

## How the backend works

- Passwords are hashed with scrypt and a random salt; plain passwords are never stored.
- Login sessions are a signed, HttpOnly, SameSite cookie valid for 14 days.
- Data lives in Netlify Blobs (built in, nothing to configure).
- Protections: same-origin check on writes, input validation, login rate limiting (8 failures per email per 15 min), registration limit per IP.

## Not included

- Email verification and "forgot password" (these need an email-sending service).
- To remove a user, delete their entries in Netlify's Blobs UI (stores `users`, `userdata`).
