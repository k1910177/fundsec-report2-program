package main

import (
	"crypto/rand"
	"fmt"

	"github.com/k1910177/fundsec-report2-program/aes"
)

// Number of plaintexts
const N = 256

func generatePlaintexts(nb int) [][]byte {
	constant_part := make([]byte, nb*4)
	rand.Read(constant_part)

	plaintexts := make([][]byte, N)
	for i := range plaintexts {
		plaintexts[i] = make([]byte, nb*4)

		// Constant property
		copy(plaintexts[i], constant_part)

		// All property
		plaintexts[i][0] = byte(i)
	}
	return plaintexts
}

func main() {
	// nr (number of rounds) is set to 4 for 4-Round AES
	nb, nk, nr := 4, 4, 4

	// Create random key for encrytion
	key := make([]byte, nk*4)
	rand.Read(key)

	// Array of subkey byte candidates
	// Maps from subkey valye that satisfies the balanced property
	candidates := make([]map[byte]int, nk*4)
	for idx := range candidates {
		candidates[idx] = make(map[byte]int)
	}

	// Run key recovery attack 3 times
	for tries := 0; tries < 3; tries++ {
		// Prepare 256 plaintexts P0, P1, ..., P255
		plaintexts := generatePlaintexts(nb)

		// Slice to store the ciphertexts of the 256 plaintexts
		ciphertexts := make([][]byte, N)
		for i := range ciphertexts {
			ciphertexts[i] = aes.Encrypt(plaintexts[i], key, nr)
		}

		// For every byte of the subkey...
		// `idx` represents the byte position of the subkey
		for idx := 0; idx < nk*4; idx++ {
			// keyGuess = [0, 0, 0, ..., 0]
			keyGuess := make([]byte, nk*4)

			// Exhaustively test for byte values 0 to 255
			for value := 0; value < 256; value++ {
				// Set the value of keyGuess at position `idx` to `value`
				keyGuess[idx] = byte(value)
				keyGuessUint32 := aes.ToUint32(keyGuess)

				// For all ciphertexts, partially decrypt with `keyGuess`
				// then take the XOR sum at position `idx`
				xor := byte(0)
				for i := range ciphertexts {
					stateBytes := make([]byte, nb*4)
					copy(stateBytes, ciphertexts[i])

					// Partially decrypt with the key guess
					state := aes.ToUint32(stateBytes)
					aes.AddRoundKey(keyGuessUint32, state)
					aes.InvSubBytes(state)

					// Compute the xor of state at position `idx`
					xor ^= aes.ToBytes(state)[idx]
				}

				// Check for balanced property
				if xor == 0 {
					// Increment the frequency of `value`
					candidates[idx][byte(value)]++
				}
			}
		}
	}

	// Do ranking test for all bytes of subkey candidates
	subkey := make([]byte, nk*4)
	for idx := range candidates {
		highest_frequency := 0
		for key, frequency := range candidates[idx] {
			// Select the most frequent byte as the final subkey
			if frequency > highest_frequency {
				highest_frequency = frequency
				subkey[idx] = key
			}
		}
	}
	fmt.Println("Computed key: ", subkey)

	// Compute the correct subkey from the key used to encrypt the plaintexts
	xk := aes.KeyExpansion(key, nr)
	subkeyAnswer := aes.ToBytes(xk[nr*4 : (nr+1)*4])
	fmt.Println("Correct key:  ", subkeyAnswer)
}
