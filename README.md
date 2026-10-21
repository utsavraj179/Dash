# Discord code login

Register and login with a Discord User ID. The bot DMs a 6-digit code, the user pastes it on the site, and they are logged in.

## Setup

1. Go to https://discord.com/developers/applications, create an application, then open Bot and copy the token. No privileged intents are needed.
2. Invite the bot to your server (OAuth2, URL Generator, scope `bot`). The bot can only DM people who share a server with it.
3. Copy `.env.example` to `.env` and paste your token.
4. Run:

```
npm install
npm start
```

5. Open http://localhost:3000

## Deploying

The bot keeps a live connection to Discord and the site uses a SQLite file, so host this on a VPS or any always-on Node host (your VPS works). Serverless hosts like Vercel will not work. Put it behind HTTPS (nginx or Caddy) and set `NODE_ENV=production`.

## How it works

- `POST /api/request-code`: checks the ID, DMs a code (stored hashed, expires in 5 minutes)
- `POST /api/verify`: checks the code (5 attempts, single use), creates the account on first register, sets a session cookie
- `GET /api/me`, `POST /api/logout`
- Rate limits protect against DM spam and code guessing

Protect your own pages by checking `/api/me` (or reuse the session lookup in `server.js`).
