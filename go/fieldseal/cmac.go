package fieldseal

import "crypto/aes"

// cmac is AES-CMAC from RFC 4493. block must be an AES cipher.
func cmac(block crypter, msg []byte) []byte {
	k1, k2 := cmacSubkeys(block)
	head, last := splitCMAC(msg, k1, k2)
	return cbcMAC(block, head, last)
}

type crypter interface {
	Encrypt(dst, src []byte)
}

func cmacSubkeys(block crypter) ([]byte, []byte) {
	zero := make([]byte, aes.BlockSize)
	l := make([]byte, aes.BlockSize)
	block.Encrypt(l, zero)
	k1 := dbl(l)
	return k1, dbl(k1)
}

func splitCMAC(msg, k1, k2 []byte) (head, last []byte) {
	n := len(msg)
	if n > 0 && n%aes.BlockSize == 0 {
		return msg[:n-aes.BlockSize], xorBytes(msg[n-aes.BlockSize:], k1)
	}
	rem := n % aes.BlockSize
	if n > rem {
		head = msg[:n-rem]
	}
	padded := make([]byte, aes.BlockSize)
	if rem > 0 {
		copy(padded, msg[n-rem:])
	}
	padded[rem] = 0x80
	return head, xorBytes(padded, k2)
}

func cbcMAC(block crypter, head, last []byte) []byte {
	state := make([]byte, aes.BlockSize)
	buf := make([]byte, aes.BlockSize)
	for len(head) > 0 {
		xorInto(buf, state, head[:aes.BlockSize])
		block.Encrypt(state, buf)
		head = head[aes.BlockSize:]
	}
	xorInto(buf, state, last)
	block.Encrypt(state, buf)
	out := make([]byte, aes.BlockSize)
	copy(out, state)
	return out
}
