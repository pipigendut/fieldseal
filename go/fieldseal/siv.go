package fieldseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// dbl is the GF(2^128) doubling used by CMAC and S2V (RFC 5297).
func dbl(in []byte) []byte {
	out := make([]byte, aes.BlockSize)
	var carry byte
	for i := aes.BlockSize - 1; i >= 0; i-- {
		next := in[i] >> 7
		out[i] = (in[i] << 1) | carry
		carry = next
	}
	if in[0]&0x80 != 0 {
		out[aes.BlockSize-1] ^= 0x87
	}
	return out
}

func xorBytes(left, right []byte) []byte {
	out := make([]byte, len(left))
	xorInto(out, left, right)
	return out
}

func xorInto(dst, left, right []byte) {
	for i := range dst {
		dst[i] = left[i] ^ right[i]
	}
}

// s2v is the S2V construction from RFC 5297. The plaintext is the last component.
func s2v(block crypter, components ...[]byte) []byte {
	if len(components) == 0 {
		one := make([]byte, aes.BlockSize)
		one[aes.BlockSize-1] = 0x01
		return cmac(block, one)
	}
	d := cmac(block, make([]byte, aes.BlockSize))
	for _, component := range components[:len(components)-1] {
		d = xorBytes(dbl(d), cmac(block, component))
	}
	// A final block of 16 bytes or more is xorend'd with D. A shorter block is
	// padded and xor'd with dbl(D). RFC 5297 A.1 is the short case and A.2 is the long case.
	return cmac(block, s2vTail(components[len(components)-1], d))
}

func s2vTail(last, state []byte) []byte {
	if len(last) >= aes.BlockSize {
		out := append([]byte(nil), last...)
		base := len(out) - aes.BlockSize
		for i := 0; i < aes.BlockSize; i++ {
			out[base+i] ^= state[i]
		}
		return out
	}
	padded := make([]byte, aes.BlockSize)
	copy(padded, last)
	padded[len(last)] = 0x80
	return xorBytes(padded, dbl(state))
}

// Bits 31 and 63 of the counter are cleared so the synthetic IV cannot collide
// with a counter block inside CTR (RFC 5297).
func clearCounterBits(synthetic []byte) []byte {
	counter := append([]byte(nil), synthetic...)
	counter[8] &= 0x7f
	counter[12] &= 0x7f
	return counter
}

func splitKey(key []byte) (macKey, ctrKey []byte, err error) {
	if len(key) != 32 && len(key) != 64 {
		return nil, nil, fmt.Errorf("siv key length %d", len(key))
	}
	half := len(key) / 2
	return key[:half], key[half:], nil
}

func seal(key, plaintext []byte, ad ...[]byte) ([]byte, error) {
	macKey, ctrKey, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	mac, err := aes.NewCipher(macKey)
	if err != nil {
		return nil, fmt.Errorf("aes mac: %w", err)
	}
	ctr, err := aes.NewCipher(ctrKey)
	if err != nil {
		return nil, fmt.Errorf("aes ctr: %w", err)
	}
	components := make([][]byte, 0, len(ad)+1)
	components = append(components, ad...)
	components = append(components, plaintext)
	synthetic := s2v(mac, components...)
	body := make([]byte, len(plaintext))
	if len(plaintext) > 0 {
		cipher.NewCTR(ctr, clearCounterBits(synthetic)).XORKeyStream(body, plaintext)
	}
	out := make([]byte, 0, aes.BlockSize+len(body))
	out = append(out, synthetic...)
	out = append(out, body...)
	return out, nil
}

func unseal(key, sealed []byte, ad ...[]byte) ([]byte, error) {
	if len(sealed) < aes.BlockSize {
		return nil, errAuth
	}
	macKey, ctrKey, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	ctr, err := aes.NewCipher(ctrKey)
	if err != nil {
		return nil, fmt.Errorf("aes ctr: %w", err)
	}
	synthetic := sealed[:aes.BlockSize]
	body := sealed[aes.BlockSize:]
	plain := make([]byte, len(body))
	if len(body) > 0 {
		cipher.NewCTR(ctr, clearCounterBits(synthetic)).XORKeyStream(plain, body)
	}
	mac, err := aes.NewCipher(macKey)
	if err != nil {
		return nil, fmt.Errorf("aes mac: %w", err)
	}
	components := make([][]byte, 0, len(ad)+1)
	components = append(components, ad...)
	components = append(components, plain)
	if subtle.ConstantTimeCompare(s2v(mac, components...), synthetic) != 1 {
		return nil, errAuth
	}
	return plain, nil
}
