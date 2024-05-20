package main

import (
	"crypto/rand"
	"fmt"

	"github.com/k1910177/fundsec-report2-program/aes"
)

const N = 256

func generatePlaintexts(nb int) [][]byte {
	constant_part := make([]byte, nb*4)
	rand.Read(constant_part)

	plaintexts := make([][]byte, N)
	for i := range plaintexts {
		plaintexts[i] = make([]byte, nb*4)
		copy(plaintexts[i], constant_part)
		plaintexts[i][0] = byte(i)
	}
	return plaintexts
}

func main() {
	nb, nk, nr := 4, 4, 4

	// Create random key
	key := make([]byte, nk*4)
	rand.Read(key)

	plaintexts := generatePlaintexts(nb)

	ciphertexts := make([][]byte, N)
	for i := range ciphertexts {
		ciphertexts[i] = aes.Encrypt(plaintexts[i], key, nr)
	}

	subkey := make([]byte, nk*4)

	for idx := 0; idx < nk*4; idx++ {
		for value := 0; value < 256; value++ {
			subkey[idx] = byte(value)
			subkeyUint32 := aes.ToUint32(subkey)

			xors := byte(0)
			for i := range ciphertexts {
				stateBytes := make([]byte, nb*4)
				copy(stateBytes, ciphertexts[i])

				state := aes.ToUint32(stateBytes)
				aes.AddRoundKey(subkeyUint32, state)
				aes.InvSubBytes(state)
				xors ^= aes.ToBytes(state)[idx]
			}
			if xors == 0 {
				break
			}
		}
	}

	xk := aes.KeyExpansion(key, nr)
	subkeyAnswer := aes.ToBytes(xk[nr*4 : (nr+1)*4])

	fmt.Println(subkey)
	fmt.Println(subkeyAnswer)

	// xk := aes.KeyExpansion(key, nr)

	// for i := range ciphertexts {
	// 	state := aes.ToUint32(ciphertexts[i])
	// 	aes.AddRoundKey(xk[nr*4:(nr+1)*4], state)
	// 	// aes.InvShiftRows(state)
	// 	aes.InvSubBytes(state)
	// 	ciphertexts[i] = aes.ToBytes(state)
	// }

	// xors := make([]byte, nb*4)
	// for i := range ciphertexts {
	// 	for j := range ciphertexts[i] {
	// 		xors[j] ^= ciphertexts[i][j]
	// 	}
	// }

	// fmt.Println(xors)
}
