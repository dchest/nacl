// Package xsalsa20 implements XSalsa20 stream cipher.
package xsalsa20

import (
	"nacl/hsalsa20"
	"nacl/salsa20"
)

var sigma = [16]byte{'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'}

// Stream generates XSalsa20 stream into the byte slice c from 24-byte nonce n
// and 32-byte key k.
func Stream(c []byte, n *[24]byte, k *[32]byte) {
	var subkey [32]byte
	hn := [16]byte{n[0],n[1],n[2],n[3],n[4],n[5],n[6],n[7],n[8],n[9],n[10],n[11],n[12],n[13],n[14],n[15]}
	sn := [8]byte{n[16],n[17],n[18],n[19],n[20],n[21],n[22],n[23]}
	hsalsa20.Core(&subkey, &hn, k, &sigma)
	salsa20.Stream(c, &sn, &subkey)
}

// Xor XORs plain-text byte slice m with XSalsa20 stream generated from 24-byte
// nonce n and 32-byte key k, and puts the result into byte slice c, which must
// have length equal to or greater than the length of m.
func Xor(c, m []byte, n *[24]byte, k *[32]byte) {
	var subkey [32]byte
	hn := [16]byte{n[0],n[1],n[2],n[3],n[4],n[5],n[6],n[7],n[8],n[9],n[10],n[11],n[12],n[13],n[14],n[15]}
	sn := [8]byte{n[16],n[17],n[18],n[19],n[20],n[21],n[22],n[23]}
	hsalsa20.Core(&subkey, &hn, k, &sigma)
	salsa20.Xor(c, m, &sn, &subkey)
}
