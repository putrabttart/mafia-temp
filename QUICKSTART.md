# Installation & Quick Start

## Prerequisites
- Node.js 18+ (check: `node -v`)
- npm (check: `npm -v`)
- Google account dengan akses Google Cloud Console

## 1. Clone/Setup Project
```bash
cd d:\WEB\TEMPMAILLLL
```

## 2. Setup Backend
```bash
cd gmail-backend

# Install dependencies
npm install

# Copy example env
cp .env.example .env

# Edit .env dengan text editor
# - Generate secure ADMIN_API_KEY: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# - Ganti GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET dari Google Cloud
```

## 3. Google Cloud Setup
1. Go to: https://console.cloud.google.com/
2. Create new project (or use existing)
3. **Enable APIs**:
   - Search & enable "Gmail API"
   - Search & enable "Google+ API"

4. **Create OAuth Credential**:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth client ID"
   - Choose "Web application"
   - Add "Authorized redirect URIs": `http://localhost:3000/oauth2callback`
   - Copy "Client ID" and "Client Secret" → paste into `.env`

5. **Configure OAuth Consent Screen**:
   - Go to "APIs & Services" → "OAuth consent screen"
   - Choose "External" (or "Internal" if internal only)
   - Fill "App name", "User support email", "Developer contact email"
   - Click "Save and Continue"
   - Add "Gmail API" scope: `.../auth/gmail.readonly`
   - Publish (atau keep in testing mode for dev)

## 4. Start Backend
```bash
npm start
# Output: "Server running on http://localhost:3000"
```

## 5. First Time Authentication
1. Open browser: http://localhost:3000/login
2. Login with Google account
3. Grant permission (read-only Gmail access)
4. You'll see: "Auth berhasil! Anda bisa menutup tab ini."
5. Token saved to `token.json` (encrypted if `TOKEN_ENCRYPTION_KEY` set)

## 6. Test Application
- **User UI**: http://localhost:3000/
  - Generate temp email alias
  - Send test email to that alias
  - View in inbox

- **Admin Dashboard**: http://localhost:3000/admin.html
  - Default admin key: `dev-admin-key` (change in `.env`)
  - Click "Test Connection" button to verify setup
  - Manage aliases, domains, view logs

## Development Commands
```bash
# Lint
npm run lint

# Format
npm run format

# Tests
npm test

# Watch mode (need nodemon)
npm install -D nodemon
npx nodemon index.js
```

## Troubleshooting

### Error: "Missing required environment variables"
- Check `.env` file exists
- Verify: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, ADMIN_API_KEY
- If using .env.example, copy and fill all values

### Error: "Not authenticated"
- Run `/login` endpoint first: http://localhost:3000/login
- Grant Gmail permission
- Refresh or retry API call

### Error: "CORS origin denied"
- Frontend trying to access from different origin
- Add frontend origin to `ALLOWED_ORIGINS` in `.env`
- Format: `http://localhost:3000,http://localhost:5173`

### Error: "Domain not allowed"
- When registering alias with unknown domain
- Go to Admin → add domain first
- Or use default: `selebungms.my.id`

### No emails appear
- Check recipient email matches alias
- Emails take 1-2 seconds to appear
- Click "Refresh" button manually
- Check Gmail account has emails to that address

## Production Deployment

### Using Docker
```bash
# Build
docker build -t gmail-tempmail .

# Run
docker run -p 3000:3000 \
  --env-file .env \
  -v /path/to/secure/token.json:/app/token.json:ro \
  gmail-tempmail
```

### Using PM2 (Node.js process manager)
```bash
npm install -g pm2

# Start
pm2 start index.js --name "gmail-tempmail"

# View logs
pm2 logs gmail-tempmail

# Restart on reboot
pm2 startup
pm2 save
```

### Reverse Proxy (Nginx example)
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Security Checklist
Before going live:
- [ ] Change `ADMIN_API_KEY` (32+ chars)
- [ ] Set `TOKEN_ENCRYPTION_KEY` (32 hex chars)
- [ ] Update `ALLOWED_ORIGINS` (remove localhost)
- [ ] Enable HTTPS (Let's Encrypt)
- [ ] Setup monitoring/alerts
- [ ] Backup `.env` securely
- [ ] Review `SECURITY.md`

## File Structure After Setup
```
gmail-backend/
├── index.js                    (main app)
├── package.json
├── .env                        (YOUR config - don't commit!)
├── token.json                  (OAuth token - encrypted - don't commit!)
├── data/
│   ├── aliases.json           (temp emails created)
│   ├── domains.json           (allowed domains)
│   ├── logs.json              (access logs)
│   └── audit.json             (admin actions)
├── test/
│   └── index.test.js          (unit tests)
├── .eslintrc.json
├── .prettierrc.json
├── .gitignore
├── .env.example               (template - COMMIT THIS)
└── Dockerfile

gmail-frontend/
├── index.html                 (user UI)
├── admin.html                 (admin dashboard)

index.html                      (root redirect)
README.md                       (documentation)
SECURITY.md                     (security guide)
QUICKSTART.md                   (this file)
```

## Next Steps
1. Configure alerting: `/health` endpoint
2. Setup log shipping (ELK, Datadog, etc)
3. Add custom domain (if using own email domain)
4. Deploy to production with HTTPS
5. Enable backup for `data/` folder
6. Setup admin rotation schedule

## Support
- Gmail API Issues: https://developers.google.com/gmail/api
- Express.js: https://expressjs.com/
- Helmet.js: https://helmetjs.github.io/
- OAuth 2.0: https://oauth.net/2/
