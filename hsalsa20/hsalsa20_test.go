package hsalsa20

import (
	"bytes"
	"testing"
)

var sigma = [16]byte{'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'}

func TestHSalsa20(t *testing.T) {
	var in [16]byte
	var out [32]byte
	k := []byte("this is 32-byte key for hsalsa20")
	var key [32]byte
	copy(key[:], k)
	correct := []byte{0x0e, 0x9a, 0x6a, 0x57, 0xfd, 0x52, 0x0e, 0xad,
		0x19, 0xb4, 0xa2, 0xf5, 0xaa, 0x3e, 0xe5, 0x51, 0x92, 0xb3, 0x88,
		0x97, 0x89, 0x6e, 0x43, 0xe7, 0x5f, 0x07, 0x44, 0x92, 0x6f, 0x8d,
		0x1c, 0xba}
	Core(&out, &in, &key, &sigma)
	if !bytes.Equal(out[:], correct) {
		t.Errorf("expected %x, got %x", correct, out)
	}
}

func BenchmarkHsalsa20(b *testing.B) {
	var in [16]byte
	var out [32]byte
	var key [32]byte
	for i := 0; i < b.N; i++ {
		Core(&out, &in, &key, &sigma)
	}
	b.SetBytes(32)
}
