# Atmakosh LLM — Teaser Website (Node.js)

Pages:
- / (Landing)
- /invite (Invite-only signup)
- /whitepapers
- /leadership
- /terms

## Run locally
```bash
npm install
npm start
# open http://localhost:3000
Where signups are stored
data/invites.ndjson (append-only, one JSON object per line)

Deploy on Hostinger Node.js
Upload this folder (or git deploy)

Set “Start command” to: npm start

Ensure environment variable PORT is provided by Hostinger (common). If not, set it.

Tip: If you want MySQL/MariaDB storage later, replace the /api/invite handler with a DB insert.
