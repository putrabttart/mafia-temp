# Gmail Temp Mail

Layanan penerima email sementara berbasis Gmail API dengan UI publik dan dashboard admin.

## Fitur utama
- Alihkan email masuk ke alias sementara; baca konten dan metadata.
- Dashboard admin untuk statistik alias, domain, dan log akses inbox.
- **Keamanan berlapis**: CORS terkontrol, rate limiting per endpoint (publik vs admin), Helmet dengan CSP, validasi input (Zod), proteksi OAuth `state`, token encryption opsional (AES-128), audit log admin actions.
- **Reliabilitas tinggi**: Concurrency limit Gmail API (p-limit), caching metadata pesan (TTL 5 menit), structured JSON logging, graceful shutdown (SIGTERM/SIGINT).
- **Observabilitas**: Health checks (`/health`, `/health/token`), audit trail untuk admin, log terstruktur dengan level (info/warn/error).
- **Deploy-ready**: Dockerfile multi-stage, `.env.example`, ESLint/Prettier, unit tests.
- Static frontend disajikan langsung dari backend (root `/` mengarah ke `gmail-frontend/index.html`).

## Prasyarat
- Node.js 18+.
- Akses ke Google Cloud Console dengan hak membuat OAuth client.

## Variabel lingkungan
Buat berkas `.env` di `gmail-backend/` menggunakan `.env.example` sebagai template.

```bash
PORT=3000
ADMIN_API_KEY=ubah-ke-api-key-kuat-anda
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
GOOGLE_CLIENT_ID=<client-id-dari-google>
GOOGLE_CLIENT_SECRET=<client-secret-dari-google>
GOOGLE_REDIRECT_URI=http://localhost:3000/oauth2callback
MAX_MESSAGES=20

# Optional: encryption key for token (32 hex chars = 16 bytes AES-128)
# Generate: node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
TOKEN_ENCRYPTION_KEY=

# Optional: custom path for token file
TOKEN_PATH=

# Optional: concurrency limit for Gmail API calls (default: 5)
GMAIL_CONCURRENCY=5

# Optional: log level (info, warn, error - default: info)
LOG_LEVEL=info
```

Keterangan:
- `ADMIN_API_KEY`: kunci yang harus dikirim lewat header `x-admin-key` pada endpoint admin.
- `ALLOWED_ORIGINS`: daftar origin yang diizinkan memanggil API (pisahkan dengan koma).
- `GOOGLE_REDIRECT_URI`: harus cocok dengan konfigurasi di Google Cloud Console.
- `MAX_MESSAGES`: batas maksimal pesan yang diambil per refresh (maks 50).
- `TOKEN_ENCRYPTION_KEY`: opsional, jika diisi token OAuth akan terenkripsi AES-128 saat disimpan.
- `GMAIL_CONCURRENCY`: batasi concurrent request ke Gmail API untuk stabilitas.

## Menyiapkan OAuth di Google Cloud Console
1. Buat project baru atau gunakan yang ada.
2. Buka **APIs & Services → OAuth consent screen**, pilih tipe (External/Internal), isi nama app dan email support, lalu simpan.
3. Tambahkan scope **Gmail API**: `.../auth/gmail.readonly` (mode read-only).
4. Buka **APIs & Services → Credentials → Create credentials → OAuth client ID**.
   - Application type: **Web application**.
   - Authorized redirect URI: `http://localhost:3000/oauth2callback` (sesuaikan dengan `GOOGLE_REDIRECT_URI`).
   - Simpan `client_id` dan `client_secret` ke `.env`.
5. Aktifkan **Gmail API** di menu **Library** untuk project tersebut.

## Menjalankan secara lokal
1. `cd gmail-backend`
2. `npm install`
3. Pastikan `.env` sudah dibuat (salin dari `.env.example`).
4. `npm start` atau `node index.js`
5. Buka `http://localhost:3000/` untuk UI publik atau `http://localhost:3000/admin.html` untuk dashboard.
6. **Penting**: Lakukan autentikasi Gmail pertama kali via `http://localhost:3000/login` sebelum menggunakan aplikasi.

## Development
```bash
# Lint code
npm run lint

# Format code
npm run format

# Run tests
npm test
```

## Docker
```bash
# Build
docker build -t gmail-tempmail .

# Run
docker run -p 3000:3000 --env-file .env gmail-tempmail
```

## Alur autentikasi Gmail
- Buka `http://localhost:3000/login` atau panggil `GET /auth/url` untuk mendapatkan URL izin Google.
- Setelah login dan memberi akses, Google mengalihkan ke `/oauth2callback` dengan kode dan state yang diverifikasi (CSRF protection).
- Token OAuth disimpan di `gmail-backend/token.json` (atau path custom via `TOKEN_PATH`).
- Jika `TOKEN_ENCRYPTION_KEY` di-set, token terenkripsi dengan AES-128-CBC.
- Revoke token via admin endpoint: `POST /auth/revoke` (requires admin key).

## Endpoints API

### Publik
- `GET /health` — Status server, token existence, config
- `GET /health/token` — Validasi token Gmail (requires auth)
- `GET /auth/url` — Generate OAuth URL + state
- `GET /login` — Redirect ke OAuth flow
- `GET /oauth2callback` — OAuth callback handler
- `GET /api/messages?alias=<email>` — List messages (requires auth)
- `GET /api/messages/:id` — Message detail (requires auth, cached)
- `POST /api/aliases` — Register alias (publik, validasi domain)

### Admin (requires `x-admin-key` header)
- `GET /api/admin/stats` — Statistik aliases/hits/domains
- `GET /api/admin/aliases` — List aliases
- `DELETE /api/admin/aliases/:address` — Hapus alias
- `GET /api/admin/domains` — List domains
- `POST /api/admin/domains` — Tambah domain (validasi Zod)
- `PUT /api/admin/domains/:name` — Toggle active status
- `DELETE /api/admin/domains/:name` — Hapus domain
- `GET /api/admin/logs?limit=50&alias=<email>` — Live monitor logs
- `DELETE /api/admin/logs` — Clear logs
- `POST /auth/revoke` — Revoke OAuth token

## Catatan keamanan
- **Admin key**: Ganti `ADMIN_API_KEY` ke nilai rahasia (min 32 karakter). Simpan di secret manager/ENV, bukan di repositori.
- **CORS**: Batasi origin lewat `ALLOWED_ORIGINS` agar hanya UI resmi yang dapat memanggil API.
- **Token OAuth**: File `token.json` berisi refresh token; lindungi file ini. Jangan commit ke git (sudah di `.gitignore`). Gunakan `TOKEN_ENCRYPTION_KEY` untuk enkripsi at-rest.
- **Rate limiting**: Publik endpoint = 100 req/menit, admin = 60 req/menit. Sesuaikan jika perlu.
- **Helmet CSP**: Allowlist CDN yang dipakai (Bootstrap, jQuery, Font Awesome) atau self-host asset.
- **Audit log**: Admin actions (tambah/hapus domain/alias, clear logs, token revoke) dicatat di `data/audit.json` dengan IP dan timestamp.
- **Input validation**: Email dan domain divalidasi dengan Zod schema sebelum diproses.
- **Graceful shutdown**: SIGTERM/SIGINT ditangani; request in-flight diberi waktu 10 detik untuk selesai.

## Struktur penting
```
gmail-backend/
  ├── index.js              — Server Express, OAuth Gmail, dan API
  ├── package.json          — Dependencies dan scripts
  ├── .env.example          — Template environment variables
  ├── .gitignore            — Exclude token, data, node_modules
  ├── Dockerfile            — Multi-stage build
  ├── test/
  │   └── index.test.js     — Unit tests (Node.js test runner)
  └── data/
      ├── aliases.json      — Registered aliases
      ├── domains.json      — Managed domains
      ├── logs.json         — Access logs (capped at 500)
      └── audit.json        — Admin audit trail (capped at 1000)

gmail-frontend/
  ├── index.html            — UI publik penerima email
  └── admin.html            — Dashboard admin

index.html                  — Root redirect ke frontend
README.md                   — Dokumentasi ini
```

## Troubleshooting
- **401 Not authenticated**: lakukan login Gmail via `/login` lalu ulangi pemanggilan API.
- **CORS origin denied**: tambahkan origin frontend ke `ALLOWED_ORIGINS` dan restart server.
- **Domain not allowed** saat membuat alias: tambahkan domain di dashboard admin atau lewat endpoint `/api/admin/domains`.
- **Token health check failed**: token expired atau revoked; re-authenticate via `/login`.
- **Rate limit exceeded**: tunggu 1 menit atau sesuaikan `windowMs` di `index.js`.

## Observabilitas & monitoring
- **Structured logs**: Semua log dalam format JSON dengan `level`, `message`, `timestamp`, dan metadata opsional.
- **Health endpoints**: 
  - `/health` — Status umum (hasToken, allowedOrigins, cacheSize)
  - `/health/token` — Validasi token Gmail dengan latency check
- **Audit trail**: Admin actions dicatat di `data/audit.json` dengan IP, user-agent, action, dan detail.
- **Cache metrics**: Cache size exposed di `/health` untuk monitoring.

## Performance optimization
- **Caching**: Message metadata dan detail di-cache 5 menit (TTL adjustable).
- **Concurrency control**: Gmail API calls dibatasi dengan p-limit (default 5 concurrent).
- **Auto-cleanup**: Cache dan pendingStates dibersihkan otomatis via interval.
- **Log rotation**: Logs dan audit capped (500 dan 1000 entries) untuk mencegah bloat.

## Lisensi
ISC (sesuaikan sesuai kebutuhan)

