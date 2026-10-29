package fieldseal

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func TestVersionMatchesReleaseFile(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(), "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(body)) != Version {
		t.Fatalf("VERSION file %q, constant %q", strings.TrimSpace(string(body)), Version)
	}
}

func TestUpdateVectors(t *testing.T) {
	if os.Getenv("UPDATE_VECTORS") == "" {
		t.Skip("set UPDATE_VECTORS=1 to rewrite testdata/vectors.json")
	}
	if err := Init(testKeyHex); err != nil {
		t.Fatal(err)
	}
	raw := mustHex(t, testKeyHex)
	derived, err := deriveSIVKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	cases := []vectorCase{
		{Column: "orang_nik", Plaintext: "3273010101010001"},
		{Column: "orang_nik", Plaintext: ""},
		{Column: "orang_nik", Plaintext: " 3273010101010001"},
		{Column: "orang_npwp_number", Plaintext: "3273010101010001"},
		{Column: "orang_address", Plaintext: "Jalan Merdeka Nomor 17, Jakarta Pusat"},
	}
	for i := range cases {
		encrypted, err := Encrypt(cases[i].Column, cases[i].Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		cases[i].Ciphertext = encrypted
	}
	payload := vectorFile{
		KeyHex:        testKeyHex,
		DerivedKeyHex: hex.EncodeToString(derived),
		HKDFSalt:      hkdfSalt,
		HKDFInfo:      hkdfInfo,
		Cases:         cases,
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	path := filepath.Join(repoRoot(), "testdata", "vectors.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVectors(t *testing.T) {
	file := readJSON[vectorFile](t, "vectors.json")
	if err := Init(file.KeyHex); err != nil {
		t.Fatal(err)
	}
	derived, err := deriveSIVKey(mustHex(t, file.KeyHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(derived) != file.DerivedKeyHex {
		t.Fatalf("derived key %s", hex.EncodeToString(derived))
	}
	for _, vector := range file.Cases {
		encrypted, err := Encrypt(vector.Column, vector.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if encrypted != vector.Ciphertext {
			t.Fatalf("column %s cipher %s", vector.Column, encrypted)
		}
		opened, err := Decrypt(vector.Column, vector.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if opened != vector.Plaintext {
			t.Fatalf("column %s plain %q", vector.Column, opened)
		}
	}
}

func TestEncryptRules(t *testing.T) {
	if err := Init(testKeyHex); err != nil {
		t.Fatal(err)
	}
	const nik = "3273010101010001"
	first, err := Encrypt("orang_nik", nik)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt("orang_nik", nik)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("expected deterministic ciphertext")
	}
	again, err := Encrypt("orang_nik", first)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatal("expected ciphertext to stay unchanged")
	}
	other, err := Encrypt("orang_npwp_number", nik)
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("expected a different column to change the ciphertext")
	}
	if _, err = Decrypt("orang_npwp_number", first); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong column: %v", err)
	}
	legacy, err := Decrypt("orang_nik", nik)
	if err != nil {
		t.Fatal(err)
	}
	if legacy != nik {
		t.Fatalf("legacy %s", legacy)
	}
	if _, err = Encrypt("", nik); !errors.Is(err, ErrColumnName) {
		t.Fatalf("column: %v", err)
	}
}

func TestInitRejectsShortKey(t *testing.T) {
	err := Init("abcd")
	if !errors.Is(err, ErrKeyLength) {
		t.Fatalf("err %v", err)
	}
}

type vectorFile struct {
	KeyHex        string       `json:"key_hex"`
	DerivedKeyHex string       `json:"derived_key_hex"`
	HKDFSalt      string       `json:"hkdf_salt"`
	HKDFInfo      string       `json:"hkdf_info"`
	Cases         []vectorCase `json:"cases"`
}

type vectorCase struct {
	Column     string `json:"column"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}
