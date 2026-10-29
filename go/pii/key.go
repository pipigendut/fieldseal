package pii

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	prefix     = "v1."
	hkdfSalt   = "coinx-pii"
	hkdfInfo   = "aes-256-siv-v1"
	rawKeySize = 32
	sivKeySize = 64
)

var (
	keyMu  sync.RWMutex
	sivKey []byte
)

// Init installs the process-wide key. keyHex is the PII_KEY shared with the Rails apps.
// Calling Init again replaces the key. Existing ciphertext cannot be opened after a
// replacement until those rows are rewritten, because encryption is deterministic.
func Init(keyHex string) error {
	raw, err := decodeKey(keyHex)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	derived, err := deriveSIVKey(raw)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	keyMu.Lock()
	sivKey = derived
	keyMu.Unlock()
	return nil
}

func decodeKey(keyHex string) ([]byte, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(keyHex), "0x")
	if len(trimmed) != rawKeySize*2 {
		return nil, ErrKeyLength
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != rawKeySize {
		return nil, ErrKeyLength
	}
	return raw, nil
}

func deriveSIVKey(raw []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, raw, []byte(hkdfSalt), []byte(hkdfInfo))
	derived := make([]byte, sivKeySize)
	if _, err := io.ReadFull(reader, derived); err != nil {
		return nil, fmt.Errorf("derive siv key: %w", err)
	}
	return derived, nil
}

func currentSIVKey() ([]byte, error) {
	keyMu.RLock()
	defer keyMu.RUnlock()
	if len(sivKey) != sivKeySize {
		return nil, ErrKeyNotSet
	}
	out := make([]byte, len(sivKey))
	copy(out, sivKey)
	return out, nil
}
