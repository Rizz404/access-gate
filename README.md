# access-gate

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

## Pasang di nginx
Lihat `deploy/nginx-snippet.conf`. Header `X-Site` = nama situs yang dibuat di UI.

## Perilaku & batasan
- Fail-closed: situs tak dikenal/nonaktif, IP tak valid, atau error DB = ditolak. Jika proses gate mati, situs terlindungi ikut menolak semua.
- `X-Real-IP` hanya dipercaya dari peer di `GATE_TRUSTED_PROXIES`; header Cloudflare diabaikan Go, nginx `real_ip` yang menanganinya.
- Panel admin tidak dilindungi whitelist ini (agar tidak terkunci); lindungi dengan password kuat + bind loopback/Tailscale.
- Sesi dan penghitung gagal login ada di memori (hilang saat restart). `/auth` membaca SQLite tiap request (tanpa cache).
- Test: `go test ./...`. Integrasi nginx nyata belum diuji.
