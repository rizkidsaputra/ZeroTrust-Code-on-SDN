# ZTNA Data Plane  `ztna_net.py`

Skrip **Mininet** yang membangun **data plane** testbed Zero Trust: ring **4 switch OVS**, satu host per switch, dengan **deny-by-default**, **static ARP**, dan **NAT gateway** agar host subjek bisa menjangkau portal login. Skrip ini hanya menyiapkan topologi + kondisi awal jaringan  aturan *allow* dipasang belakangan oleh controller.

> Konsep besarnya (arsitektur zero trust, micro-segmentation, bukti enforcement) dibahas di **laporan**. README ini fokus ke **cara kerja skrip** dan **cara menjalankannya**.

---

## Topologi

   ![topology](../attachment/topology.svg))

- **Host** di **port 1** tiap switch; **ring** pakai **port 2** (egress) & **port 3** (ingress); **nat0** menempel di **port 4** pada s1.
- Ring: `s1–s2–s3–s4–s1`.

| Host | IP | MAC | Segmen |
|------|-----|-----|--------|
| h1 | 10.0.0.1 | `00:00:00:00:00:01` | research (subjek) |
| h2 | 10.0.0.2 | `00:00:00:00:00:02` | server |
| h3 | 10.0.0.3 | `00:00:00:00:00:03` | iot |
| h4 | 10.0.0.4 | `00:00:00:00:00:04` | guest |

---

## Peta kode `ztna_net.py`

| Fungsi / kelas | Tugas |
|----------------|-------|
| `RingTopo.build()` | Bangun 4 switch (`OpenFlow13`) + 1 host tiap switch (host di port 1), lalu link ring `s1–s2–s3–s4–s1` (egress port 2, ingress port 3) |
| `s1_port_to(net, node)` | Cari nomor port s1 yang tersambung ke node tertentu  dipakai untuk menemukan link `s1 ↔ nat0` |
| `setup_static_arp(net, nat)` | Pasang **ARP statis** antar semua host + ke gateway; NAT juga tahu MAC tiap host. Tanpa ARP broadcast → ring tidak loop |
| `start_services(net)` | Jalankan TCP listener uji: **h2** `:8080 :9000 :22`, **h3** `:80` (h4 sengaja kosong)  untuk menguji port tier **Full** vs **Limited** |
| `install_pdp_carveout(net, nat)` | Pasang 2 flow `priority=200` di s1 agar h1 **selalu** bisa menjangkau portal login di VM1 (`ODL_IP`)  satu arah keluar via NAT, satu arah balik ke port 1 |
| `main()` | Rangkai semuanya (lihat urutan di bawah) + buka CLI Mininet |

### Urutan setup di `main()`

1. Buat `Mininet` dengan `RemoteController` `c0` → `ODL_IP:6653`, switch `OVSSwitch`, tanpa auto-MAC.
2. Tambah node **NAT** `nat0` (`GW_IP`) yang otomatis menempel ke s1.
3. `net.start()`, lalu untuk tiap switch set **`fail-mode=secure`** + flow **`priority=0 actions=drop`** → **deny-by-default** (tanpa fallback NORMAL).
4. `nat.configDefault()` (default route host + masquerade) + pin `GW_IP`, dan set `default via GW_IP` di tiap host.
5. `setup_static_arp()` → `start_services()` → `install_pdp_carveout()`.
6. Cetak info, buka `CLI(net)`; saat CLI ditutup, `net.stop()`.

---

## Konfigurasi

Semua ada di bagian atas skrip:

| Variabel | Default | Keterangan |
|----------|---------|-----------|
| `ODL_IP` | `192.168.13.4` | VM1  controller + portal login yang dituju host |
| `OF_PORT` | `6653` | Port OpenFlow ke remote controller |
| `GW_IP` | `10.0.0.254` | IP NAT gateway di s1 (sisi data-plane) |
| `HOSTS` | h1–h4 | `name → (ip, mac, segment)`  sumber kebenaran IP/MAC/segmen |
| service ports | h2 `8080/9000/22`, h3 `80` | Diatur di `start_services()`; ubah kalau butuh port uji lain |

---

## Cara menjalankan

```bash
sudo mn -c                    # bersihkan sisa Mininet sebelumnya
sudo python3 ztna_net.py      # bangun ring + NAT + ARP + services + carveout
```

Setelah topologi up, dari dalam CLI Mininet:

```bash
# sanity: host research harus bisa menjangkau portal (VM1)
mininet> h1 ping -c1 192.168.13.4

# login dari host research
mininet> h1 python3 pep_client.py
```

Contoh keluaran saat skrip siap:

```
nat0: ip=10.0.0.254 mac=42:85:22:e6:bd:84
Ready. Log in from the research host:
  mininet> h1 python3 pep_client.py
Sanity:  mininet> h1 ping -c1 192.168.13.4   (should reach the PDP host)
```

---

## Catatan penting

- **Deny-by-default** ditegakkan skrip ini sendiri: `fail-mode=secure` + flow `priority=0 drop` di tiap switch. Tidak ada penerusan otomatis  jalur baru hanya terbuka jika ada flow *allow* yang dipasang controller.
- **Static ARP itu wajib** di topologi ring: menghilangkan ARP broadcast yang bisa memicu **loop**. IP/MAC diambil dari dict `HOSTS`, jadi ubah keduanya di satu tempat.
- **NAT masquerade** mengurus return path dari VM1, sehingga VM1 tidak perlu route balik ke `10.0.0.0/24`.
- **Service uji** hanya untuk memvalidasi kebijakan port (mis. Full membuka semua port h2, Limited hanya sebagian); **h4 (guest) sengaja tidak melayani apa pun** agar mudah menguji isolasi.
- Jalankan dengan `sudo` (Mininet butuh root).
