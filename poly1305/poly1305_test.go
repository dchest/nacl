// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package poly1305

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"testing"
)

var testData = []struct {
	in, k, correct []byte
}{
	{
		[]byte("Hello world!"),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0xa6, 0xf7, 0x45, 0x00, 0x8f, 0x81, 0xc9, 0x16, 0xa2, 0x0d, 0xcc, 0x74, 0xee, 0xf2, 0xb2, 0xf0},
	},
	{
		make([]byte, 32),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0x49, 0xec, 0x78, 0x09, 0x0e, 0x48, 0x1e, 0xc6, 0xc2, 0x6b, 0x33, 0xb9, 0x1c, 0xcc, 0x03, 0x07},
	},
	{
		make([]byte, 2007),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0xda, 0x84, 0xbc, 0xab, 0x02, 0x67, 0x6c, 0x38, 0xcd, 0xb0, 0x15, 0x60, 0x42, 0x74, 0xc2, 0xaa},
	},
	{
		make([]byte, 2007),
		make([]byte, 32),
		make([]byte, 16),
	},
}

func TestOneTimeAuth(t *testing.T) {
	for i, v := range testData {
		out := make([]byte, 16)
		OneTimeAuth(out, v.in, v.k)
		if !bytes.Equal(out, v.correct) {
			t.Errorf("[%d] expected %x, got %x", i, v.correct, out)
		}
	}
}

func BenchmarkOneTimeAuth1K(b *testing.B) {
	b.StopTimer()
	k := make([]byte, 32)
	in := make([]byte, 1024)
	out := make([]byte, 16)
	b.SetBytes(int64(len(in)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		OneTimeAuth(out, in, k)
	}
}

func BenchmarkOneTimeAuth64(b *testing.B) {
	b.StopTimer()
	k := make([]byte, 32)
	in := make([]byte, 64)
	out := make([]byte, 16)
	b.SetBytes(int64(len(in)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		OneTimeAuth(out, in, k)
	}
}

func BenchmarkHMACMD5_1K(b *testing.B) {
	b.StopTimer()
	k := make([]byte, 32)
	in := make([]byte, 1024)
	out := make([]byte, 0, 32)
	b.SetBytes(int64(len(in)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		h := hmac.New(md5.New, k)
		h.Write(in)
		h.Sum(out[0:0])
	}
}
func BenchmarkHMACMD5_64(b *testing.B) {
	b.StopTimer()
	k := make([]byte, 32)
	in := make([]byte, 64)
	out := make([]byte, 0, 32)
	b.SetBytes(int64(len(in)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		h := hmac.New(md5.New, k)
		h.Write(in)
		h.Sum(out[0:0])
	}
}
