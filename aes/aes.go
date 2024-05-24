package aes

import "encoding/binary"

func ToUint32(src []byte) []uint32 {
	dst := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		dst[i] = binary.BigEndian.Uint32(src[4*i:])
	}
	return dst
}

func ToBytes(src []uint32) []byte {
	dst := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(dst[4*i:4*(i+1)], src[i])
	}
	return dst
}

func Encrypt(src, key []byte, nr int) []byte {
	xk := KeyExpansion(key, nr)

	state := ToUint32(src)

	AddRoundKey(xk[0:4], state)

	for i := 1; i < nr; i++ {
		SubBytes(state)
		ShiftRows(state)
		MixColumns(state)
		AddRoundKey(xk[i*4:(i+1)*4], state)
	}

	SubBytes(state)
	ShiftRows(state)
	AddRoundKey(xk[nr*4:(nr+1)*4], state)

	dst := ToBytes(state)

	return dst
}
