package aes

import "encoding/binary"

func subw(w uint32) uint32 {
	return uint32(sbox[w>>24])<<24 |
		uint32(sbox[w>>16&0xff])<<16 |
		uint32(sbox[w>>8&0xff])<<8 |
		uint32(sbox[w&0xff])
}

func rotw(w uint32) uint32 {
	return w<<8 | w>>24
}

func KeyExpansion(key []byte, nr int) []uint32 {
	nk := len(key) / 4
	xk := make([]uint32, nk*(nr+1))

	var i int

	// Copy key to xk
	for i = 0; i < nk; i++ {
		xk[i] = binary.BigEndian.Uint32(key[4*i:])
	}

	for ; i < len(xk); i++ {
		t := xk[i-1]
		if i%nk == 0 {
			t = subw(rotw(t)) ^ (uint32(powx[i/nk-1]) << 24)
		} else if nk > 6 && i%nk == 4 {
			t = subw(t)
		}
		xk[i] = xk[i-nk] ^ t
	}

	return xk
}

// AddRoundKey XORs the round key xk with the state and puts the result in the state
func AddRoundKey(xk, state []uint32) {
	state[0] ^= xk[0]
	state[1] ^= xk[1]
	state[2] ^= xk[2]
	state[3] ^= xk[3]
}

// SubBytes replaces each byte of the state with its substitution in the S-box.
func SubBytes(state []uint32) {
	for i := 0; i < 4; i++ {
		state[i] = uint32(sbox[state[i]>>24])<<24 |
			uint32(sbox[state[i]>>16&0xff])<<16 |
			uint32(sbox[state[i]>>8&0xff])<<8 |
			uint32(sbox[state[i]&0xff])
	}
}

func InvSubBytes(state []uint32) {
	for i := 0; i < 4; i++ {
		state[i] = uint32(inv_sbox[state[i]>>24])<<24 |
			uint32(inv_sbox[state[i]>>16&0xff])<<16 |
			uint32(inv_sbox[state[i]>>8&0xff])<<8 |
			uint32(inv_sbox[state[i]&0xff])
	}
}

// ShiftRows modifies the state to shift rows to the left
// First row is left unchanged
// Second row is shifted by one cell
// Third row is shifted by two cells
// Fourth row is shifted by three cells
func ShiftRows(state []uint32) {
	var s0, s1, s2, s3 uint32
	s0 = state[0]&(0xff<<24) | state[1]&(0xff<<16) | state[2]&(0xff<<8) | state[3]&0xff
	s1 = state[1]&(0xff<<24) | state[2]&(0xff<<16) | state[3]&(0xff<<8) | state[0]&0xff
	s2 = state[2]&(0xff<<24) | state[3]&(0xff<<16) | state[0]&(0xff<<8) | state[1]&0xff
	s3 = state[3]&(0xff<<24) | state[0]&(0xff<<16) | state[1]&(0xff<<8) | state[2]&0xff
	state[0], state[1], state[2], state[3] = s0, s1, s2, s3
}

func InvShiftRows(state []uint32) {
	var s0, s1, s2, s3 uint32
	s0 = state[0]&(0xff<<24) | state[3]&(0xff<<16) | state[2]&(0xff<<8) | state[1]&0xff
	s1 = state[1]&(0xff<<24) | state[0]&(0xff<<16) | state[3]&(0xff<<8) | state[2]&0xff
	s2 = state[2]&(0xff<<24) | state[1]&(0xff<<16) | state[0]&(0xff<<8) | state[3]&0xff
	s3 = state[3]&(0xff<<24) | state[2]&(0xff<<16) | state[1]&(0xff<<8) | state[0]&0xff
	state[0], state[1], state[2], state[3] = s0, s1, s2, s3
}

// MixColumns updates the state with the MixColumns operation of the AES. It uses
// two pre-computed tables that implement multiplication by 2 and by 3 in GF(256).
func MixColumns(state []uint32) {
	var b0, b1, b2, b3, d0, d1, d2, d3 byte

	for i := 0; i < 4; i++ {
		b0 = byte(state[i] >> 24)
		b1 = byte(state[i] >> 16)
		b2 = byte(state[i] >> 8)
		b3 = byte(state[i])

		d0 = gmul2[b0] ^ gmul3[b1] ^ b2 ^ b3
		d1 = gmul2[b1] ^ gmul3[b2] ^ b3 ^ b0
		d2 = gmul2[b2] ^ gmul3[b3] ^ b0 ^ b1
		d3 = gmul2[b3] ^ gmul3[b0] ^ b1 ^ b2

		state[i] = uint32(d0)<<24 | uint32(d1)<<16 | uint32(d2)<<8 | uint32(d3)

	}
}
