// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xsalsa20

import (
	"bytes"
	"testing"
)

var testData = []struct {
	m, n, k, correct []byte
}{
	{
		[]byte("Hello world!"),
		[]byte("24-byte nonce for xsalsa"),
		[]byte("this is 32-byte key for xsalsa20"),
		[]byte{0x00, 0x2d, 0x45, 0x13, 0x84, 0x3f, 0xc2, 0x40, 0xc4, 0x01, 0xe5, 0x41},
	},
	{
		make([]byte, 64),
		[]byte("24-byte nonce for xsalsa"),
		[]byte("this is 32-byte key for xsalsa20"),
		[]byte{0x48, 0x48, 0x29, 0x7f, 0xeb, 0x1f, 0xb5, 0x2f, 0xb6,
			0x6d, 0x81, 0x60, 0x9b, 0xd5, 0x47, 0xfa, 0xbc, 0xbe, 0x70,
			0x26, 0xed, 0xc8, 0xb5, 0xe5, 0xe4, 0x49, 0xd0, 0x88, 0xbf,
			0xa6, 0x9c, 0x08, 0x8f, 0x5d, 0x8d, 0xa1, 0xd7, 0x91, 0x26,
			0x7c, 0x2c, 0x19, 0x5a, 0x7f, 0x8c, 0xae, 0x9c, 0x4b, 0x40,
			0x50, 0xd0, 0x8c, 0xe6, 0xd3, 0xa1, 0x51, 0xec, 0x26, 0x5f,
			0x3a, 0x58, 0xe4, 0x76, 0x48},
	},
}

func TestXor(t *testing.T) {
	var n [24]byte
	var k [32]byte
	for i, v := range testData {
		c := make([]byte, len(v.m))
		copy(n[:], v.n)
		copy(k[:], v.k)
		Xor(c, v.m, &n, &k)
		if !bytes.Equal(c, v.correct) {
			t.Errorf("[%d] expected %x, got %x", i, v.correct, c)
		}
	}
}

var (
	keyarr [32]byte
	key = &keyarr
	noncearr [24]byte
	nonce = &noncearr
	msg = make([]byte, 8<<10)
)

func BenchmarkXOR1K(b *testing.B) {
	b.StopTimer()
	out := make([]byte, 1024)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Xor(out, msg[:1024], nonce, key)
	}
	b.SetBytes(1024)
}

func BenchmarkXOR8K(b *testing.B) {
	b.StopTimer()
	out := make([]byte, len(msg))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Xor(out, msg, nonce, key)
	}
	b.SetBytes(int64(len(msg)))
}
