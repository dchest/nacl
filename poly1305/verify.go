package poly1305

import "crypto/subtle"

// Verify returns true if the 16-byte authenticator h is correct
// for input in and 32-key k.
func Verify(h, in, k []byte) bool {
	var tmp [16]byte
	correct := tmp[:]
	OneTimeAuth(correct, in, k)
	return subtle.ConstantTimeCompare(correct, h) == 1
}
