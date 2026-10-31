# access-gate

Repo: https://github.com/Rizz404/access-gate

Manajer whitelist IP untuk website lain. Nginx memanggil `/auth` lewat `auth_request`;
IP yang tidak ada di daftar situs itu ditolak (403). Perubahan berlaku langsung, tanpa reload nginx.

## Jalankan
```
echo -n 'passwordmu' | go run . hash        # hasilnya untuk GATE_ADMIN_HASH
export GATE_ADMIN_HASH='$2a$10$...'
go run .
```
Admin UI: `http://127.0.0.1:9180` · endpoint nginx: `http://127.0.0.1:9181/auth`

| Env | Default | Fungsi |
|---|---|---|
| `GATE_ADMIN_HASH` | (wajib) | bcrypt password admin |
| `GATE_DB` | `access-gate.db` | file SQLite |
| `GATE_ADDR_ADMIN` | `127.0.0.1:9180` | alamat UI |
| `GATE_ADDR_AUTH` | `127.0.0.1:9181` | alamat `/auth` (jaga tetap loopback) |
| `GATE_TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | peer yang boleh mengirim `X-Real-IP` |
| `GATE_COOKIE_SECURE` | kosong | `1` jika UI dilayani lewat HTTPS |
| `GATE_WEBHOOK_SECRET` | kosong | secret webhook GitHub; kosong = auto-update mati |
| `GATE_UPDATE_REPO` | (wajib jika webhook aktif) | `owner/nama` repo sumber binary |
| `GATE_STAGE_DIR` | folder `GATE_DB` | tempat binary baru disiapkan |

## UI (htmx + Tailwind)
`static/htmx.min.js` (htmx 2.0.11) dan `static/app.css` (hasil build Tailwind) ikut di-embed ke binary, tanpa CDN.
Ubah tampilan di `templates/*.html`, lalu build ulang CSS (Tailwind v4, butuh Node sementara):
```
mkdir -p /tmp/tw && cd /tmp/tw && npm i tailwindcss @tailwindcss/cli
printf '@import "tailwindcss";\n@source "%s/templates";\n' "$OLDPWD" > input.css
npx @tailwindcss/cli -i input.css -o "$OLDPWD/static/app.css" --minify
```

## Pasang di nginx
Lihat `deploy/nginx-snippet.conf`. Header `X-Site` = nama situs yang dibuat di UI.

## Auto-update dari GitHub
Push ke `main` -> GitHub Actions (`.github/workflows/build.yml`) test + build -> binary diunggah ke release `latest`
-> webhook `workflow_run` memanggil `POST /hooks/github` -> server mengunduh binary dari URL release yang tetap,
cek sha256, menaruhnya di `GATE_STAGE_DIR`, lalu keluar; systemd (`deploy/access-gate.service`) memasang dan menjalankan binary baru.
- Webhook: payload `application/json`, event **Workflow runs**, secret = `GATE_WEBHOOK_SECRET` (HMAC-SHA256 diverifikasi).
- Hanya event `completed` + `success` di branch `main` dari `GATE_UPDATE_REPO` yang diproses; binary identik dilewati.
- sha256 berasal dari release yang sama, jadi melindungi dari file rusak, bukan dari repo yang dibobol.

## Perilaku & batasan
- Fail-closed: situs tak dikenal/nonaktif, IP tak valid, atau error DB = ditolak. Jika proses gate mati, situs terlindungi ikut menolak semua.
- Mode proxy: IP yang ditolak dijawab status 444 (tanpa body); nginx memetakan ke `return 444` sehingga koneksi ditutup tanpa respons dan tidak ada tulisan "forbidden". Mode `auth_request` tetap 403 karena nginx mewajibkannya.
- `X-Real-IP` hanya dipercaya dari peer di `GATE_TRUSTED_PROXIES`; header Cloudflare diabaikan Go, nginx `real_ip` yang menanganinya.
- Panel admin tidak dilindungi whitelist ini (agar tidak terkunci); lindungi dengan password kuat + bind loopback/Tailscale.
- Sesi dan penghitung gagal login ada di memori (hilang saat restart). `/auth` membaca SQLite tiap request (tanpa cache).
- Test: `go test ./...`. Integrasi nginx nyata belum diuji.
