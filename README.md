# Judol Blocklist (otomatis)

Bot yang mengumpulkan domain judi online, memverifikasinya (DNS + isi halaman), lalu menerbitkan blocklist berformat AdGuard. Semua proses berjalan di **GitHub Actions**, jadi tidak membebani laptop atau server AdGuard Home-mu.

## Cara kerja

```
sumber kandidat ──► collect ──► db.json ──► verify ──► build ──► lists/*.txt
 - CertStream (sertifikat TLS baru)          │  DNS resolve       - judol-auto.txt
 - crt.sh (kata kunci spesifik)              │  ambil halaman     - judol-reviewed.txt
 - GitHub Issues (laporan orang)             │  skor kata kunci   - judol-auto.domains.txt
 - candidate_lists (opsional)                │  prune yang mati   - data/review-queue.tsv
 - redirect dari situs judol lain            ▼                    - data/sources.tsv
```

Status tiap domain di `data/db.json`:

| Status | Arti |
|---|---|
| `candidate` | baru ditemukan, belum dicek |
| `auto` | lolos verifikasi, masuk `judol-auto.txt` |
| `review` | meragukan, menunggu keputusan manusia (`data/review-queue.tsv`) |
| `reject` | halaman tidak menunjukkan judol |
| `dead` | tidak resolve / sudah mati, dibuang dari daftar |

Domain lama dicek ulang bergiliran. Jika mati atau berubah selama 5 pengecekan berturut-turut (`prune_after`), domain dikeluarkan dari daftar agar list tetap ramping.

## Isi repo

| Path | Fungsi |
|---|---|
| `judolbot.py` | seluruh logika bot |
| `config.json` | kata kunci, ambang skor, batas, sumber (edit di sini, bukan di kode) |
| `data/whitelist.txt` | domain yang **tidak boleh** diblokir |
| `data/approved.txt` | domain yang sudah kamu cek manual dan pasti judol |
| `data/candidates.txt` | antrean kandidat manual (juga diisi dari Issues) |
| `data/db.json` | basis data status domain (dikelola bot) |
| `lists/` | hasil akhir untuk AdGuard |
| `.github/workflows/update.yml` | jadwal otomatis tiap 12 jam |
| `.github/workflows/ingest-issue.yml` | mengubah laporan Issue jadi kandidat |
| `.github/ISSUE_TEMPLATE/` | formulir lapor domain dan lapor salah blokir |

## Pemasangan (sekitar 10 menit)

1. **Buat repo baru** di GitHub, misalnya `judol-blocklist` (publik supaya raw URL bisa dipakai AdGuard tanpa token).
2. **Unggah semua isi folder ini** ke repo. Pastikan folder tersembunyi `.github` ikut terunggah. Lewat web: *Add file → Upload files*, lalu seret isi folder hasil ekstrak ZIP. Kalau `.github` tidak ikut terseret, buat manual lewat *Add file → Create new file* dengan nama `.github/workflows/update.yml` dan seterusnya.
3. **Izinkan Actions menulis ke repo:** *Settings → Actions → General → Workflow permissions → Read and write permissions → Save*.
4. **Buat label** (opsional tapi rapi): tab *Issues → Labels* → `lapor-domain` dan `salah-blokir`.
5. **Jalankan pertama kali:** tab *Actions → Update blocklist → Run workflow*. Run pertama lebih lama karena CertStream mendengarkan sekitar 3 menit dan ada verifikasi awal.
6. **Cek hasil:** setelah selesai, folder `lists/` berisi daftar dan ada commit dari `judolbot`.

Di tab Actions, run pertama bisa saja menghasilkan sedikit domain (bahkan nol). Itu normal: CertStream hanya menangkap sertifikat yang terbit selama jendela dengarnya, jadi daftar tumbuh seiring run berikutnya.

## Memakai di AdGuard Home

*Filters → DNS blocklists → Add blocklist → Add a custom list*, lalu isi:

```
https://raw.githubusercontent.com/GregOliv/judol-blocklist/main/lists/judol-auto.txt
https://raw.githubusercontent.com/GregOliv/judol-blocklist/main/lists/judol-reviewed.txt
```

Ganti `GregOliv/judol-blocklist` bila nama repomu berbeda. AdGuard Home memperbarui otomatis (interval bisa diatur di *Settings → General settings → Filters update interval*).

Pengguna lain bisa memakai URL yang sama di AdGuard (aplikasi/ekstensi), uBlock Origin, atau Pi-hole (`judol-auto.domains.txt` untuk Pi-hole).

Bot ini hanya menyimpan domain **baru** yang belum ada di sumber upstream (`upstream_lists` di `config.json`). Jadi sebaiknya kamu tetap langganan list gambling yang sudah mapan, misalnya HaGeZi Gambling dan Block List Project Gambling, lalu tambahkan list ini sebagai pelengkap.

## Alur kerja sehari-hari

**Meninjau antrean `review`.** Buka `data/review-queue.tsv` (di GitHub bisa dilihat sebagai tabel). Untuk tiap domain:
- Memang judol: tambahkan ke `data/approved.txt`.
- Bukan judol: tambahkan ke `data/whitelist.txt`.

Commit perubahan itu; run berikutnya (atau *Run workflow* manual) yang menerapkannya.

**Ada domain salah blokir.** Tambahkan ke `data/whitelist.txt`. Subdomain ikut terlindungi, dan domain itu langsung hilang dari daftar pada build berikutnya.

**Menambah domain manual.** Tulis di `data/candidates.txt`, satu per baris (`domain` lalu TAB lalu sumber, sumber boleh dikosongkan). Domain tetap diverifikasi. Kalau sudah pasti judol, langsung masukkan ke `data/approved.txt`.

**Laporan orang lain.** Mereka membuka *Issues → New issue → Lapor domain judol*. Workflow otomatis memasukkan maksimal 20 domain per issue ke antrean verifikasi lalu menutup issue. Domain hanya diblokir jika lolos verifikasi, jadi laporan iseng tidak langsung memblokir apa pun.

## Perlindungan false positive

1. **Wajib ada kata kunci judol di isi halaman.** Blokir otomatis butuh sedikitnya 2 istilah kuat (misalnya "slot gacor", "maxwin", "rtp live") dan skor minimal 6. Istilah umum seperti "login", "bonus", "deposit" saja tidak cukup.
2. **Domain institusi tidak pernah masuk otomatis.** Akhiran `.go.id`, `.ac.id`, `.sch.id`, `.desa.id`, `.gov`, `.edu`, dan sejenisnya selalu masuk `review`. Ini untuk kasus situs resmi yang diretas dan disisipi halaman judol.
3. **Blokir di tingkat domain terdaftar.** `||contoh.com^` sudah mencakup semua subdomain. Untuk hosting bersama (`blogspot.com`, `github.io`, `pages.dev`, dan sebagainya) yang diblokir hanya subdomain pelakunya, bukan platformnya.
4. **Whitelist selalu menang.**

## Penyesuaian (`config.json`)

| Kunci | Fungsi |
|---|---|
| `strong_terms`, `weak_terms` | istilah penilai halaman; tambahkan istilah baru yang kamu temui |
| `name_terms` | kata di nama domain yang dijadikan kandidat dari CertStream/crt.sh |
| `thresholds` | `auto` (skor minimal blokir otomatis), `min_strong_auto`, `review` |
| `certstream.seconds` | lama mendengarkan sertifikat per run (makin lama, makin banyak kandidat) |
| `crtsh.keywords` | kata kunci pencarian crt.sh; pilih yang spesifik (`gacor`, `maxwin`), jangan `slot` |
| `verify.workers` | jumlah pengecekan paralel di runner |
| `verify.prune_after` | berapa kali gagal berturut-turut sebelum domain dibuang |
| `max_entries` | batas ukuran daftar; jaga tetap wajar supaya AdGuard Home tetap ringan |
| `upstream_lists` | list yang dipakai untuk menghindari duplikasi |
| `candidate_lists` | URL daftar domain tambahan sebagai kandidat, misalnya feed domain baru terdaftar |

Kata kunci bukan pengganti penilaian manusia. Pantau `review-queue.tsv` beberapa minggu pertama, lalu sesuaikan `strong_terms` dan `thresholds` berdasarkan hasil nyata.

## Menjalankan di komputer sendiri (opsional)

Tidak diperlukan, tetapi bisa untuk uji coba. Proses ini memakai jaringan dan sedikit CPU (20 pengecekan paralel), jadi turunkan `verify.workers` dan `certstream.seconds` di `config.json` bila dijalankan di laptop yang terbatas.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python judolbot.py run
```

Perintah terpisah: `collect`, `verify`, `build`.

## Pemecahan masalah

- **Workflow gagal saat push:** cek langkah 3 di atas (izin baca dan tulis).
- **`lists/` kosong:** normal pada run pertama bila belum ada kandidat yang lolos. Jalankan lagi beberapa kali, atau isi `data/candidates.txt` untuk memberi bibit.
- **CertStream gagal terhubung:** server publik kadang mati. Bot mencatat peringatan dan tetap lanjut dengan sumber lain (crt.sh, Issues).
- **crt.sh timeout:** memang sering terjadi; bot mencoba dua kali lalu lanjut.
- **URL sumber upstream 404:** bot hanya memberi peringatan. Perbarui URL di `config.json`.
- **Jadwal berhenti:** GitHub bisa menonaktifkan workflow terjadwal pada repo yang lama tidak aktif. Aktifkan lagi lewat tab Actions.
- **Kuota Actions:** repo publik gratis tanpa batas menit. Untuk repo privat, jadwal 12 jam memakai kira-kira 15 menit per run.

## Batasan yang perlu diketahui

- Bot hanya memeriksa **halaman depan**. Halaman judol yang disembunyikan di sub-path situs sah tidak terdeteksi (dan memang tidak seharusnya memblokir domain induknya).
- Situs judol yang memakai cloaking (menampilkan konten berbeda untuk bot) bisa lolos; laporan manual membantu menutup celah ini.
- Pemblokiran DNS bisa dilewati oleh perangkat yang memakai DNS atau DoH sendiri.
- Bot mengambil halaman situs yang tidak dikenal. Untuk keamanan, IP privat/loopback ditolak dan setiap redirect diperiksa ulang, tetapi tetap jalankan hanya di GitHub Actions atau lingkungan terisolasi.
