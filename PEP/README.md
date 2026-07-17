# ZTNA CLI Client  `pep_client.py`

Klien **CLI login** untuk testbed Zero Trust. Dijalankan **dari dalam host** (`mininet> h1 python3 pep_client.py`): mengirim kredensial + identitas host (IP/MAC) ke **PDP**, lalu menampilkan hasil keputusan akses (role, trust, tier, resource yang di-grant) beserta **token** sesi untuk revoke. Hanya pakai **standard library**  tidak perlu `pip install` di namespace host.

> Model trust score, kebijakan, dan cara enforcement dibahas di **laporan**. README ini fokus ke **cara kerja klien** dan **cara memakainya**.

---

## Peta kode `pep_client.py`

| Fungsi | Tugas |
|--------|-------|
| `local_identity()` | Deteksi **best-effort** IP & MAC data-plane host ini: baca `ip -o addr show`, ambil interface ber-IP `10.0.0.x`, lalu baca MAC dari `/sys/class/net/<dev>/address`. Nilai ini ikut dikirim saat login |
| `post(path, payload)` | Helper HTTP **POST JSON** via `urllib` (stdlib). Kembalikan `(status, body)`; menangani `HTTPError` (mis. 401/403) dan `URLError` (PDP tak tercapai) |
| `main()` | Alur login interaktif: baca identitas → prompt `username`/`password` (`getpass`) → `POST /login` → tampilkan **GRANTED/DENIED** → cetak token + cara revoke |
| dispatch di `__main__` | Kalau argumen `--logout <token>` → `POST /logout`; selain itu → jalankan `main()` |

---

## Konfigurasi

| Variabel | Default | Keterangan |
|----------|---------|-----------|
| `PDP_URL` | `http://192.168.13.4:5000` | Alamat portal login yang dituju klien |

---

## Cara pakai

**Login** (dari dalam host subjek):

```bash
mininet> h1 python3 pep_client.py
```

Klien akan menanyakan `username` dan `password`, lalu menampilkan hasilnya.

**Logout / revoke** (pakai token dari hasil login):

```bash
python3 pep_client.py --logout <token>
```

---

## Contoh keluaran

**Akses diberikan** (`alice`, role research, skor tinggi):

```
== ZTNA login ==  (this host: 10.0.0.1 / 00:00:00:00:00:01)
username: alice
password:
GRANTED  role=research  trust=90.0  tier=FULL
  iot      ports [80]           path s1 -> 2 -> 3
  server   ports [8080,9000,22] path s1 -> 2

session token: 009252ddb355
flows stay active until you revoke them:
    python3 pep_client.py --logout 009252ddb355
```

**Akses ditolak** (kredensial salah, atau trust di bawah ambang):

```
DENIED (403): trust below threshold  [tier=DENIED trust=35.0]
  reasons: mac/ip binding mismatch, outside allowed hours
```

**PDP tak tercapai:**

```
! cannot reach PDP: <alasan>
```

---

## Catatan penting

- **Stdlib only** (`getpass`, `json`, `subprocess`, `urllib`)  sengaja tanpa dependensi eksternal supaya bisa langsung jalan di namespace host tanpa `pip`.
- **Identitas host dikirim otomatis:** IP & MAC dari interface `10.0.0.x` dideteksi lalu disertakan di request login, sehingga ikut dinilai oleh server (mis. kecocokan MAC↔IP).
- **Password aman di layar:** dibaca dengan `getpass`, tidak ditampilkan saat diketik.
- **Akses bersifat sewaan:** flow tetap aktif sampai di-revoke via `--logout <token>`  simpan token-nya. `detail.reasons` pada respons DENIED membantu men-*debug* kenapa skor turun.
