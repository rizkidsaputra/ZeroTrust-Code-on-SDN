# ZTNA Policy Decision Point (PDP)

**PDP** berbasis Flask untuk testbed **Zero Trust Architecture di atas SDN**. Tugasnya: menerima login, menghitung **trust score**, mencocokkan dengan **policy (RBAC)**, lalu memasang **flow** ke switch OVS lewat OpenDaylight (RESTCONF). PDP hanya *memutuskan* dan *push flow*   ia tidak pernah membawa trafik data. Enforcement (deny-by-default) terjadi di flow table OVS.

> Latar belakang konsep   NIST SP 800-207, model trust score, continuous verification, dan bukti enforcement   sudah dibahas di **laporan Week 3**. README ini fokus ke **cara kerja kode** dan **cara menjalankannya**.

---

## Struktur repo

| File | Jalan di | Isi |
|------|----------|-----|
| `pdp.py` | VM1 (bareng ODL) | Policy Decision Point   autentikasi, trust score, provisioning flow |
| `ztna_net.py` | VM2 | Topologi Mininet ring 4-switch + NAT gateway + static ARP |
| `pep_client.py` | dalam host subjek | Klien login (dijalankan dari `mininet> h1 ...`) |

**Testbed:** VM1 `192.168.13.4` (control plane: OpenDaylight + PDP), VM2 `192.168.13.3` (data plane: OVS ring). Host: `h1` Research (subjek), `h2` Server, `h3` IoT, `h4` Guest   masing-masing di IP `10.0.0.1–4` pada port 1 switch-nya.

---

## Peta kode `pdp.py`

Kode dibagi jadi blok-blok berikut (urut dari atas file):

| Blok | Isi / variabel utama | Tugas |
|------|----------------------|-------|
| **Config** | `ODL_*`, `PDP_IP`, `DATA_SUBNET`, `ALLOWED_HOURS`, `W_R/W_C/W_B`, `TIER_*` | Parameter testbed & model trust |
| **Topology** | `HOST`, `ADJ`, `LINK_PORT`, `HOST_PORT` | Peta ring **statis** (tidak pakai LLDP): segmen↔IP↔MAC↔switch, tetangga tiap switch, dan port egress antar-switch |
| **Policy** | `POLICY`, `MIN_SCORE`, `LIMITED_PORTS` | Matriks RBAC (role → resource → port) + ambang skor per resource + port yang tersisa di tier Limited |
| **Trust scoring** | `context_score()`, `behaviour_score()`, `trust_score()` | Hitung `C`, `B`, lalu `T = wR·R + wC·C + wB·B` dan tentukan tier |
| **Path & flow** | `shortest_path()`, `_flow_json()`, `_put_flow()`, `_delete_flow()`, `_install_along()`, `provision_session()` | BFS cari jalur di ring, bangun body flow RESTCONF, dan pasang/hapus flow di tiap switch sepanjang jalur (maju + balik) |
| **Decision** | `evaluate()` | Terjemahkan `(role, T, tier)` → `{resource: {ports}}` yang akhirnya di-provision |
| **HTTP API** | `login()`, `logout()`, `health()` | Endpoint Flask |

### Alur satu login (dalam istilah kode)

`POST /login` → cek kredensial di `USERS` → `trust_score()` (kalau tier `DENIED` → 403) → `evaluate()` menghasilkan resource+port yang di-grant → untuk tiap pasangan, `provision_session()` memasang flow **dua arah** via RESTCONF → simpan `token` di `SESSIONS` → balas JSON `{token, trust, tier, granted}`.

`POST /logout` menghapus semua flow milik token (DELETE), mengembalikan jaringan ke deny-default.

### Endpoint

| Method | Path | Fungsi |
|--------|------|--------|
| `POST` | `/login` | Autentikasi + skoring + provisioning; balas `token` & `granted` |
| `POST` | `/logout` | Hapus semua flow milik `token` |
| `GET`  | `/health` | Cek hidup + jumlah sesi aktif |

### Kenapa flow-nya aman

Tiap flow yang dipasang match ke `eth-src` + `ipv4-src` + `ipv4-dst` + `tcp-dst-port`   jadi **terikat identitas** (bukan aturan "buka semua"). Match `eth-src` inilah yang menahan spoofing.

---

## Konfigurasi yang sering diubah

Semua ada di blok atas `pdp.py`:

| Variabel | Default | Keterangan |
|----------|---------|-----------|
| `USERS` | `alice/research123`, `bob/guest123` | Kredensial + role |
| `POLICY` | research→{server,iot}, iot→{server}, guest→{} | Entitlement per role |
| `ALLOWED_HOURS` | `range(0, 24)` | Jendela waktu; mis. `range(7, 22)` = 07:00–21:59 |
| `W_R, W_C, W_B` | `0.5, 0.3, 0.2` | Bobot trust score |
| `TIER_FULL, TIER_LIMITED` | `70, 40` | Ambang tier |
| `R_BY_ROLE` | research 80 … guest 30 | Skor identitas per role |
| `MIN_SCORE`, `LIMITED_PORTS` | server 70 / iot 40 · {80, 8080} | Aturan tier per resource |
| `ODL_HOST/PORT/AUTH` | `192.168.13.4:8181`, `admin/admin` | Target RESTCONF |

---

## Daftar user (testbed)

Kredensial ini dipakai saat login lewat `pep_client.py`. Ada di dictionary `USERS` pada `pdp.py`:

| Username | Password | Role | Segmen | Ringkas hak akses |
|----------|----------|------|--------|-------------------|
| `alice` | `research123` | `research` | Research (h1) | Server (`8080, 9000, 22`) + IoT (`80`)   subjek utama demo |
| `bob` | `guest123` | `guest` | Guest (h4) | Tidak ada (terisolasi penuh)   untuk uji deny |

> Hanya untuk **testbed riset**   password plaintext, jangan dipakai di produksi. Tambah user baru dengan menambah entri di `USERS` dan pastikan role-nya ada di `POLICY`.

---

## Cara menjalankan

**1. VM1   pastikan OpenDaylight up dengan feature yang benar (tanpa `l2switch`):**

```bash
# di dalam Karaf
feature:install odl-restconf odl-openflowplugin-flow-services-rest
```

**2. VM2   bangun topologi ring:**

```bash
sudo mn -c
sudo python3 ztna_net.py
```

**3. VM1   jalankan PDP:**

```bash
python3 pdp.py               # bind 0.0.0.0:5000
python3 pdp.py --dry-run     # hanya cetak JSON RESTCONF, tanpa panggil ODL
```

**4. Login dari dalam host subjek:**

```bash
mininet> h1 python3 pep_client.py
```

Contoh keluaran (`alice`, role research, sinyal bersih → `T=90`, `FULL`):

```
GRANTED  role=research  trust=90.0  tier=FULL
  iot      ports [80]           path s1 -> 2 -> 3
  server   ports [8080,9000,22] path s1 -> 2
session token: 009252ddb355
```

---

## Cek cepat

```bash
# lihat flow yang terpasang (terikat identitas)
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s2 | grep priority=50

# allow: Research -> Server
mininet> h1 curl -s -m3 10.0.0.2:8080 | head

# deny: Guest terisolasi (output kosong = di-drop)
mininet> h4 curl -s -m3 10.0.0.2:8080
```

Matriks pengujian lengkap (allow/deny) ada di **laporan Week 3, bagian Verifikasi Penegakan**.

---

## Catatan penting

- **Wajib lepas `odl-l2switch`.** Ia learning-switch yang forward reaktif dan membocorkan deny-by-default. Kalau Guest masih bisa nembus Server, kemungkinan besar fitur ini masih aktif.
- **Reachability PDP** disediakan `ztna_net.py` lewat NAT gateway `10.0.0.254` + static ARP; jalur data lain tetap tertutup sampai PDP memasang flow.
- Kredensial `admin/admin` dan password plaintext hanya untuk **testbed riset**, bukan produksi.
