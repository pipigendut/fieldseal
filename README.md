# fieldseal

Enkripsi kolom database yang deterministik, dipakai bersama oleh service Rails dan Go. Plaintext yang sama pada nama kolom yang sama selalu menjadi ciphertext yang sama, jadi `find_by`, `WHERE kolom = ?`, dan unique index tetap jalan tanpa kolom tambahan.

Algoritmanya AES-256-SIV. Nilai kosong tetap kosong. Data lama yang belum berprefix `v1.` tetap terbaca sebagai plaintext.

## Kunci

Satu nilai `FIELDSEAL_KEY` di setiap service yang membaca atau menulis kolom itu. Bentuknya 32 byte, ditulis sebagai 64 karakter hex.

```sh
openssl rand -hex 32
```

Mengganti kunci membuat ciphertext lama tidak bisa dibuka, dan lookup ikut berubah. Setelah ganti kunci, seluruh baris harus ditulis ulang.

## Rails

Tambahkan di `Gemfile`:

```ruby
gem "fieldseal", git: "git@github.com:pipigendut/fieldseal.git", tag: "v0.1.0"
```

Set `FIELDSEAL_KEY`. Railtie membaca env itu dan memasang helper ke ActiveRecord. Di model, daftarkan nama kolom database:

```ruby
class Orang < ApplicationRecord
  encrypts_deterministic :orang_nik
end
```

Setelah itu kode biasa tetap memakai NIK asli:

```ruby
ora.orang_nik = "3273010101010001"
ora.save!
ora.orang_nik                              # plaintext
Orang.find_by(orang_nik: "3273010101010001")
```

`where(orang_nik: nik)` ikut mengenkripsi nilai pencarian. Bentuk SQL mentah tidak:

```ruby
Orang.where("orang_nik = ?", Fieldseal.encrypt(nik, column: "orang_nik"))
```

`update_columns` dan `update_column` juga melewati type. Kalau memakai itu, enkripsi dulu dengan `Fieldseal.encrypt`.

## Go

```bash
go get github.com/pipigendut/fieldseal/go@v0.1.0
```

```go
import "github.com/pipigendut/fieldseal/go/fieldseal"

if err := fieldseal.Init(os.Getenv("FIELDSEAL_KEY")); err != nil {
    return err
}
```

Di struct, nama kolom pada tag `column` harus sama dengan nama yang didaftarkan di Rails:

```go
OrangNIK string `gorm:"column:orang_nik;serializer:fieldseal"`
```

`Create`, `Save`, dan `First` mengenkripsi dan mendekripsi lewat serializer. Query SQL mentah tidak:

```go
enc, err := fieldseal.Encrypt("orang_nik", nik)
db.Where("orang_nik = ?", enc)
```

`Where("orang_nik = ?", nik)` membandingkan plaintext dengan ciphertext, jadi tidak ketemu.

## Migrasi baris lama

Selama nilai di database belum berprefix `v1.`, record yang di-load tetap mengembalikan plaintext. `find_by` tidak menemukan baris itu, karena pencarian sudah berupa ciphertext. Tulis ulang setiap baris sebelum lookup dipakai.

Rails:

```ruby
Orang.find_each do |orang|
  raw = orang.read_attribute_before_type_cast("orang_nik")
  next if raw.blank? || Fieldseal.ciphertext?(raw)

  orang.update_column(:orang_nik, Fieldseal.encrypt(raw, column: "orang_nik"))
end
```

Go: baca lewat model (plaintext lama tetap terbuka), lalu `Save`. Save menulis ciphertext. Setelah itu lookup memakai `fieldseal.Encrypt`.

Pasang library ini di setiap proses yang membaca atau menulis kolom itu. Proses yang belum dipasang akan menampilkan ciphertext atau menimpa kolom dengan plaintext.

## Batasan

- `ILIKE` dan pencarian sebagian tidak bisa pada ciphertext. Ganti ke pencarian persis.
- Beberapa NIK kosong tetap boleh, sama seperti validasi `allow_blank` sekarang. Unique index penuh akan menolak lebih dari satu string kosong. Kalau index ditambahkan, buat partial index yang mengabaikan `''`.
- SDK tidak membuang spasi. `"3273 01"` dan `"327301"` menjadi dua ciphertext. Samakan normalisasi di semua service sebelum nilai masuk ke model.
- Plaintext yang memang diawali `v1.` tidak dienkripsi lagi.
- Kolom `string` (`varchar(255)`) cukup untuk NIK. Field yang lebih panjang perlu `text`, karena ciphertext bertambah 16 byte lalu di-base64.
- Nama yang diberikan ke `encrypts_deterministic` dan tag `column` di Go adalah nama kolom database, misalnya `orang_nik`.

## Test

```sh
make vectors   # tulis ulang testdata/vectors.json dari implementasi Go
make test
```

`testdata/rfc5297.json` dan `testdata/rfc4493.json` adalah vektor standar. `testdata/vectors.json` adalah kontrak wire format antara Ruby dan Go. Kunci di file itu hanya untuk test.

Kalau `seal` / `Encrypt` berubah, jalankan `make vectors`, lalu `make test`. Kedua bahasa harus lulus pada file yang sama.
