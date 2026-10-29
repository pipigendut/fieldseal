// Package pii encrypts database columns with deterministic AES-256-SIV.
//
// The same plaintext and column name always produce the same ciphertext, so
// equality lookups and unique indexes keep working on that column. Ciphertext
// uses the v1. prefix and is interchangeable with the coinx-pii Ruby gem.
//
// Call Init with PII_KEY before Encrypt, Decrypt, or a GORM read/write. The
// key is 32 bytes encoded as 64 hex characters and must be identical on every
// service that touches an encrypted column.
//
// GORM models opt in with the serializer tag. The column tag is the associated
// data, so it must be the database column name used by the Rails model:
//
//	OrangNIK string `gorm:"column:orang_nik;serializer:coinx_pii"`
//
// Where("orang_nik = ?", nik) does not pass through the serializer. Encrypt the
// lookup value first.
package pii
