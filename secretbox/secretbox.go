// Package secretbox implements secret-key authenticated encryption.
package secretbox

import (
	"nacl/poly1305"
	"nacl/xsalsa20"
)

const (
	NonceSize = 24
	KeySize   = 32

	ZeroBytes    = 32
	BoxZeroBytes = 16
)

func CreateTo(c, m []byte, n *[24]byte, k *[32]byte) {
	if len(m) < ZeroBytes {
		panic("secretbox: message must expected to contain ZeroBytes")
	}
	xsalsa20.Xor(c, m, n, k)
	poly1305.OneTimeAuth(c[16:], c[32:], c[0:32])
	for i := 0; i < 16; i++ {
		c[i] = 0
	}
}

func OpenTo(m, c []byte, n *[24]byte, k *[32]byte) bool {
	if len(c) < BoxZeroBytes + poly1305.OutputSize {
		panic("secretbox: ciphertext is too short")
	}
	var subkey [32]byte
	xsalsa20.Stream(subkey[:], n, k)
	if !poly1305.Verify(c[16:32], c[32:], subkey[:]) {
		return false
	}
	xsalsa20.Xor(m, c, n, k)
	for i := 0; i < 32; i++ {
		m[i] = 0
	}
	return true
}

// Create returns a new encrypted and authenticated box from the given byte
// slice m with 24-byte nonce n and 32-byte key k.
//
// The returned byte slice is 16 bytes longer than m (it contains 16-byte
// authenticator concatenated with encrypted message).
//
// This function allocates memory for the returned byte slice.
func Create(m []byte, n *[24]byte, k *[32]byte) []byte {
	mpad := make([]byte, ZeroBytes+len(m))
	copy(mpad[ZeroBytes:], m)
	xsalsa20.Xor(mpad, mpad, n, k)
	poly1305.OneTimeAuth(mpad[16:], mpad[32:], mpad[0:32])
	return mpad[BoxZeroBytes:]
}

// Open opens the encrypted and authenticated box c with 24-byte nonce n and
// 32-byte key k, and returns the decrypted message.
//
// If authentication fails (for example, the box has been tampered with or
// became corrupted, or the key or nonce is incorrect), the function returns
// nil.
//
// The returned byte slice is 16 bytes shorter than c (it contains the original
// encrypted message).
//
// This function allocates memory for the returned byte slice.
func Open(c []byte, n *[24]byte, k *[32]byte) []byte {
	if len(c) < 16 {
		return nil
	}
	cpad := make([]byte, BoxZeroBytes+len(c))
	copy(cpad[BoxZeroBytes:], c)
	var tmp [32]byte
	subkey := tmp[:]
	xsalsa20.Stream(subkey, n, k)
	if !poly1305.Verify(cpad[16:32], cpad[32:], subkey) {
		return nil
	}
	xsalsa20.Xor(cpad, cpad, n, k)
	return cpad[ZeroBytes:]
}
