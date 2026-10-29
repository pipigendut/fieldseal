package fieldseal

import (
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCMACRFC4493(t *testing.T) {
	file := readJSON[rfc4493File](t, "rfc4493.json")
	for _, vector := range file.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			block, err := aes.NewCipher(mustHex(t, vector.Key))
			if err != nil {
				t.Fatal(err)
			}
			got := cmac(block, mustHex(t, vector.Message))
			if hex.EncodeToString(got) != vector.MAC {
				t.Fatalf("mac %s", hex.EncodeToString(got))
			}
		})
	}
}

func TestSIVRFC5297(t *testing.T) {
	file := readJSON[rfc5297File](t, "rfc5297.json")
	for _, vector := range file.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			key := mustHex(t, vector.Key)
			plain := mustHex(t, vector.Plaintext)
			ads := make([][]byte, 0, len(vector.Ads))
			for _, ad := range vector.Ads {
				ads = append(ads, mustHex(t, ad))
			}
			sealed, err := seal(key, plain, ads...)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(sealed) != vector.Output {
				t.Fatalf("output %s", hex.EncodeToString(sealed))
			}
			opened, err := unseal(key, sealed, ads...)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(opened) != vector.Plaintext {
				t.Fatalf("opened %s", hex.EncodeToString(opened))
			}
		})
	}
}

func TestAES256RoundTrip(t *testing.T) {
	key := bytesRepeat(0x11, sivKeySize)
	for _, size := range []int{0, 1, 15, 16, 17, 40} {
		plain := bytesRepeat(0x61, size)
		sealed, err := seal(key, plain, []byte("orang_nik"))
		if err != nil {
			t.Fatal(err)
		}
		opened, err := unseal(key, sealed, []byte("orang_nik"))
		if err != nil {
			t.Fatal(err)
		}
		if string(opened) != string(plain) {
			t.Fatalf("size %d", size)
		}
		if _, err = unseal(key, sealed, []byte("orang_name")); err == nil {
			t.Fatalf("size %d opened with the wrong column", size)
		}
	}
}

type rfc4493File struct {
	Cases []struct {
		Name    string `json:"name"`
		Key     string `json:"key"`
		Message string `json:"message"`
		MAC     string `json:"mac"`
	} `json:"cases"`
}

type rfc5297File struct {
	Cases []struct {
		Name      string   `json:"name"`
		Key       string   `json:"key"`
		Ads       []string `json:"ads"`
		Plaintext string   `json:"plaintext"`
		Output    string   `json:"output"`
	} `json:"cases"`
}

func readJSON[T any](t *testing.T, name string) T {
	t.Helper()
	var out T
	body, err := os.ReadFile(testdataPath(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func testdataPath(name string) string {
	return filepath.Join(repoRoot(), "testdata", name)
}

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
