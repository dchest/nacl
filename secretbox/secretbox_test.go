// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package secretbox

import (
	"testing"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
)

func encryptAndDecrypt(t *testing.T, m []byte) {
	var k [32]byte
	var n [24]byte
	c := Create([]byte(m), &n, &k)
	dec := Open(c, &n, &k)
	if dec == nil {
		t.Errorf("failed to decrypt")
		return
	}
	if string(dec) != string(m) {
		t.Errorf("bad decrypted text: expected %q, got %q", m, dec)
		return
	}
}

func TestCreateAndOpen(t *testing.T) {
	encryptAndDecrypt(t, []byte("Hello world"))
	encryptAndDecrypt(t, make([]byte, 10000))
	encryptAndDecrypt(t, []byte{})
}

func TestCreateToAndOpenTo(t *testing.T) {
	var k [KeySize]byte
	var n [NonceSize]byte
	text := []byte("Hello world")
	m := make([]byte, len(text) + ZeroBytes)
	copy(m[ZeroBytes:], text)
	c := make([]byte, len(m))
	CreateTo(c, m, &n, &k)
	dec := make([]byte, len(c))
	if !OpenTo(dec, c, &n, &k) {
		t.Errorf("failed to open box")
	}
	// Message would be: m[ZeroBytes:]
	if string(dec) != string(m) {
		t.Errorf("bad decrypted text: expected %q, got %q", m, dec)
		return
	}
}

func TestOpenInvalid(t *testing.T) {
	var k [KeySize]byte
	var n [NonceSize]byte
	c := make([]byte, 200)
	if Open(c, &n, &k) != nil {
		t.Errorf("opened invalid box")
	}
	// Zero-length ciphertext.
	if Open([]byte{}, &n, &k) != nil {
		t.Errorf("opened invalid box")
	}
}

var (
	keyarr [32]byte
	key = &keyarr
	noncearr [24]byte
	nonce = &noncearr
	msg = make([]byte, 8<<10)
)

func BenchmarkCreate50(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Create(msg[:50], nonce, key)
	}
	b.SetBytes(50)
}

func BenchmarkCreate1K(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Create(msg[:1024], nonce, key)
	}
	b.SetBytes(1024)
}

func BenchmarkCreate8K(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Create(msg, nonce, key)
	}
	b.SetBytes(int64(len(msg)))
}

func BenchmarkOpenValid1K(b *testing.B) {
	b.StopTimer()
	c := Create(msg[:1024], nonce, key)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Open(c, nonce, key)
	}
	b.SetBytes(int64(len(c)))
}

func BenchmarkOpenValid8K(b *testing.B) {
	b.StopTimer()
	c := Create(msg, nonce, key)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Open(c, nonce, key)
	}
	b.SetBytes(int64(len(c)))
}

func BenchmarkOpenInvalid1K(b *testing.B) {
	b.StopTimer()
	c := Create(msg[:1024], nonce, key)
	c[100] = 1 // make cipher text non-verifiable.
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Open(c, nonce, key)
	}
	b.SetBytes(int64(len(c)))
}

func BenchmarkOpenInvalid8K(b *testing.B) {
	b.StopTimer()
	c := Create(msg, nonce, key)
	c[100] = 1 // make cipher text non-verifiable.
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Open(c, nonce, key)
	}
	b.SetBytes(int64(len(c)))
}

// For comparison, benchmark AES-256-CTR + HMAC-SHA-256.
func aesCtrHmacBox(m, n, k []byte) []byte {
	block, err := aes.NewCipher(k)
	if err != nil {
		panic("AES error")
	}
	stream := cipher.NewCTR(block, n)
	out := make([]byte, 32+len(m))
	stream.XORKeyStream(out[32:], m)
	h := hmac.New(sha256.New, out[0:32])
	h.Write(out[32:])
	mac := h.Sum(nil)
	copy(out, mac)
	return out
}
