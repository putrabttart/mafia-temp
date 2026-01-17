# PBS Mail

Aplikasi temp mail berbasis Next.js (App Router) dengan UI publik dan dashboard admin.

## Fitur utama
- Alias email sementara, inbox menampilkan pesan terbaru (dibatasi 3 pada UI publik).
- Dashboard admin: statistik alias/domain/log, tambah/hapus domain & alias, clear logs, token revoke.
- Keamanan: header `x-admin-key` untuk API admin, validasi input (Zod), optional token encryption AES-128, audit log admin actions.
- Observabilitas: health checks (`/health`, `/health/token`), structured logging, cache metrics.
- Deploy-ready: Next.js 14, API routes, Dockerfile, `.env.example` (gunakan `.env.local`).

## Stack singkat
- Frontend/Backend: Next.js 14 (App Router)
- Auth admin UI: Supabase Auth (email/password) + admin API key
- Gmail access: Google APIs (read-only)
- Data: JSON files di `/data` (aliases, domains, logs, audit)

## Variabel lingkungan (root .env.local)
```
PORT=3000
ADMIN_API_KEY=<ganti-dengan-kunci-kuat>
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173,http://localhost:8080
GOOGLE_CLIENT_ID=<client-id-google>
GOOGLE_CLIENT_SECRET=<client-secret-google>
GOOGLE_REDIRECT_URI=https://<domain-anda>/oauth2callback
MAX_MESSAGES=20

TOKEN_ENCRYPTION_KEY=<opsional-32-hex-untuk-AES-128>
TOKEN_PATH=

NEXT_PUBLIC_SUPABASE_URL=https://xkacsdvkpniafudevwvq.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=sb_publishable_BpsbHQApiJVo41bccRj3-g_MgL6Ck2X
```

## Alur login admin (email/password Supabase)
1. Buat user di Supabase Auth (email & password) dan auto-confirm.
2. Buka `/admin/login`, isi email/password Supabase → Login.
3. Setelah login, di `/admin` masukkan `Admin API Key` (header `x-admin-key`) untuk memuat data admin.

## Endpoint utama
- Publik: `/api/messages?alias=...`, `/api/messages/:id`, `/api/aliases`.
- Admin: `/api/admin/stats`, `/api/admin/aliases`, `/api/admin/domains`, `/api/admin/logs`, `/auth/revoke` (semua butuh `x-admin-key`).
- Health: `/health`, `/health/token`.

## Cara jalan lokal
```bash
npm install
npm run dev
# Buka http://localhost:3000 untuk user UI
# Buka http://localhost:3000/admin/login untuk login admin
```

## Deploy cepat (Railway/Vercel)
- Set semua ENV di dashboard (lihat daftar di atas).
- Pastikan `GOOGLE_REDIRECT_URI` pakai domain produksi.
- Deploy; Next.js akan build dan serve API + UI.

## Catatan keamanan
- Ganti `ADMIN_API_KEY` (≥32 char) dan simpan di secret manager.
- Batasi `ALLOWED_ORIGINS` ke domain resmi.
- Lindungi `token.json` (tidak di-commit; sudah di `.gitignore`).
- Gunakan `TOKEN_ENCRYPTION_KEY` untuk enkripsi token Gmail.

## Struktur ringkas
```
app/
  page.jsx          (UI publik PBS Mail)
  admin/page.jsx    (Dashboard admin, protected Supabase session + x-admin-key)
  admin/login/      (Halaman login admin email/password)
  api/...           (API routes Next.js)
lib/server/...      (Runtime, Gmail, validation, logging)
lib/supabaseClient.js
data/               (aliases.json, domains.json, logs.json, audit.json)
.env.local
```

## Troubleshooting singkat
- 401 / admin API: pastikan header `x-admin-key` benar.
- 404 /api/admin/logs: pastikan deployment terbaru (redeploy jika perlu).
- OAuth error redirect_uri_mismatch: samakan `GOOGLE_REDIRECT_URI` dengan yang di Google Console.
- Tidak bisa login admin: user belum dibuat/confirm di Supabase Auth.

