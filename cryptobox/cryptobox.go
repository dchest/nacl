// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cryptobox implements public-key authenticated encryption.
package cryptobox

import (
	"code.google.com/p/go.crypto/curve25519"
	"nacl/hsalsa20"
	"nacl/secretbox"
)

var beforen [16]byte
var sigma = [16]byte{'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'}

const NonceSize = secretbox.NonceSize

func Before(k *[32]byte, pk, sk *[32]byte) {
	curve25519.ScalarMult(k, sk, pk)
	hsalsa20.Core(k, &beforen, k, &sigma)
}

func CreateAfter(m []byte, n *[24]byte, k *[32]byte) []byte {
	return secretbox.Create(m, n, k)
}

func OpenAfter(c []byte, n *[24]byte, k *[32]byte) []byte {
	return secretbox.Open(c, n, k)
}

func Create(m []byte, n *[24]byte, pk, sk *[32]byte) []byte {
	var k [32]byte
	Before(&k, pk, sk)
	return CreateAfter(m, n, &k)
}

func Open(c []byte, n *[24]byte, pk, sk *[32]byte) []byte {
	var k [32]byte
	Before(&k, pk, sk)
	return OpenAfter(c, n, &k)
}

func CreateTo(c, m []byte, n *[24]byte, pk, sk *[32]byte) {
	var k [32]byte
	Before(&k, pk, sk)
	secretbox.CreateTo(c, m, n, &k)
}

func OpenTo(m, c []byte, n *[24]byte, pk, sk *[32]byte) bool {
	var k [32]byte
	Before(&k, pk, sk)
	return secretbox.OpenTo(m, c, n, &k)
}
