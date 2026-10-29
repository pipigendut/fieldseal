package fieldseal

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Ciphertext reports whether stored uses the v1 wire format.
func Ciphertext(stored string) bool {
	return strings.HasPrefix(stored, prefix)
}

// Encrypt seals plaintext for a database column.
//
// column is associated data, so it must be the database column name. The same
// plaintext under two column names does not compare equal. An empty plaintext
// stays empty and is not encrypted. A value that already has the v1. prefix is
// returned unchanged so a second save does not encrypt it again.
func Encrypt(column, plaintext string) (string, error) {
	if plaintext == "" || Ciphertext(plaintext) {
		return plaintext, nil
	}
	if column == "" {
		return "", fmt.Errorf("encrypt: %w", ErrColumnName)
	}
	key, err := currentSIVKey()
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	sealed, err := seal(key, []byte(plaintext), []byte(column))
	if err != nil {
		return "", fmt.Errorf("encrypt column %s: %w", column, err)
	}
	return prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value written by Encrypt.
//
// A stored value without the v1. prefix is returned unchanged so rows that
// still hold plaintext keep loading during migration. Tampered ciphertext,
// the wrong column name, or the wrong key returns ErrDecrypt.
func Decrypt(column, stored string) (string, error) {
	if stored == "" || !Ciphertext(stored) {
		return stored, nil
	}
	if column == "" {
		return "", fmt.Errorf("decrypt: %w", ErrColumnName)
	}
	key, err := currentSIVKey()
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, prefix))
	if err != nil {
		return "", fmt.Errorf("decrypt column %s: %w", column, ErrDecrypt)
	}
	plain, err := unseal(key, raw, []byte(column))
	if err != nil {
		return "", fmt.Errorf("decrypt column %s: %w", column, ErrDecrypt)
	}
	return string(plain), nil
}
