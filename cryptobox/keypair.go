// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptobox

import (
	"crypto/rand"
	"io"

	"code.google.com/p/go.crypto/curve25519"
)

const (
	PublicKeySize = 32
	SecretKeySize = 32
)

// KeyPair generates a 32-byte public key pk and a 32-byte secret key sk.
func KeyPair(pk, sk *[32]byte) {
	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		panic("cryptobox: error reading random bytes: " + err.Error())
	}
	curve25519.ScalarBaseMult(pk, sk)
}
