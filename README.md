# X Investment — Real Backend (Demo)

This package contains a simple demo of **X Investment** with a minimal Node.js backend that simulates mobile payments and stores user data in JSON files.

## Files
- `public/index.html` — frontend (talks to the backend at `/api/*`)
- `server/server.js` — Express server with endpoints: signup, login, deposit, withdraw, payment simulation
- `package.json` — dependencies and start script
- `server/data/` — will be created automatically and holds `users.json` and `payments.json`

## Quick start (local)
1. Install dependencies:
   ```bash
   npm install
   ```
2. Start server:
   ```bash
   npm start
   ```
   Server listens on port 3000 by default. Open `http://localhost:3000` in your browser.
3. Notes:
   - This is a simulation. For production you must use HTTPS, a proper database, secure session auth, and integrate a real payments provider (e.g., Safaricom MPesa Daraja).
   - Passwords are hashed with PBKDF2 (200k iterations) in this demo.
