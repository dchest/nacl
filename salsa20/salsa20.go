// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package salsa20 implements Salsa20 stream cipher.
package salsa20

var sigma = [16]byte{'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'}

// Stream generates Salsa20 stream into the byte slice c from 8-byte nonce n
// and 32-byte key k.
func Stream(c []byte, n *[8]byte, k *[32]byte) {
	var block [64]byte
	in := [16]byte{n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], 0,0,0,0,0,0,0,0}

	pin := &in
	pblock := &block

	for len(c) >= 64 {
		Core(pblock, pin, k, &sigma)
		for i := 0; i < 64; i++ {
			c[i] = pblock[i]
		}
		u := uint32(1)
		for i := 8; i < 16; i++ {
			u += uint32(in[i])
			in[i] = byte(u)
			u >>= 8
		}
		c = c[64:]
	}

	if len(c) > 0 {
		Core(pblock, pin, k, &sigma)
		for i := range c {
			c[i] = pblock[i]
		}
	}
}

// Xor XORs plain-text byte slice m with Salsa20 stream generated from 8-byte
// nonce n and 32-byte key k, and puts the result into byte slice c, which must
// have length equal to or greater than the length of m.
func Xor(c, m []byte, n *[8]byte, k *[32]byte) {
	var block [64]byte
	in := [16]byte{n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], 0,0,0,0,0,0,0,0}

	pin := &in
	pblock := &block

	for len(m) >= 64 {
		Core(pblock, pin, k, &sigma)
		for i := 0; i < 64; i++ {
			c[i] = m[i] ^ pblock[i]
		}
		u := uint32(1)
		for i := 8; i < 16; i++ {
			u += uint32(in[i])
			in[i] = byte(u)
			u >>= 8
		}
		c = c[64:]
		m = m[64:]
	}

	if len(m) > 0 {
		Core(pblock, pin, k, &sigma)
		for i, v := range m {
			c[i] = v ^ pblock[i]
		}
	}
}
