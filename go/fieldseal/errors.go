package fieldseal

import "errors"

var (
	// ErrKeyNotSet is returned when Encrypt or Decrypt runs before Init.
	ErrKeyNotSet = errors.New("key is not set")
	// ErrKeyLength is returned when FIELDSEAL_KEY is not 64 hexadecimal characters.
	ErrKeyLength = errors.New("key must be 64 hex characters")
	// ErrColumnName is returned when the database column name is empty.
	ErrColumnName = errors.New("column name is empty")
	// ErrDecrypt is returned when ciphertext cannot be opened with this key and column.
	ErrDecrypt = errors.New("decrypt failed")
)

var errAuth = errors.New("siv authentication failed")
