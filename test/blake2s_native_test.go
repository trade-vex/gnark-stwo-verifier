package stwo_test

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/blake2s"
)

func TestBlake2sWithStandardLibrary(t *testing.T) {
	// LEAF_PREFIX from stwo: "leaf" followed by 60 zeros
	leafPrefix := make([]byte, 64)
	copy(leafPrefix, []byte("leaf"))

	// Test with 8 values [1,2,3,4,5,6,7,8]
	values := []uint32{1, 2, 3, 4, 5, 6, 7, 8}
	
	h, _ := blake2s.New256(nil)
	h.Write(leafPrefix)
	for _, v := range values {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], v)
		h.Write(buf[:])
	}
	hash := h.Sum(nil)
	
	// Convert to uint32 words
	var words [8]uint32
	for i := 0; i < 8; i++ {
		words[i] = binary.LittleEndian.Uint32(hash[i*4 : i*4+4])
	}
	
	t.Logf("Go (stdlib) hash: %v", words)
	
	// Expected from Rust stwo
	expected := [8]uint32{3259828632, 2314795766, 2319707334, 2178956902, 82899606, 3863158974, 844031347, 3573722985}
	t.Logf("Rust hash:        %v", expected)
	
	if words == expected {
		t.Log("MATCH!")
	} else {
		t.Error("MISMATCH!")
	}
}
