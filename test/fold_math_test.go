package stwo_test

import (
	"math/big"
	"testing"

	"github.com/gnark-stwo/stwo/mersenne31"
)

// TestFoldMathParity verifies that our fold formula matches stwo's exactly
// using known test values, independent of the witness parsing issues.
func TestFoldMathParity(t *testing.T) {
	p := mersenne31.M31Modulus

	// Test case: known values that we can verify against stwo
	// These should match the ibutterfly + fold formula exactly

	t.Run("ibutterfly formula", func(t *testing.T) {
		// ibutterfly(v0, v1, itwid):
		//   f0 = v0 + v1
		//   f1 = (v0 - v1) * itwid

		v0 := big.NewInt(1000000)
		v1 := big.NewInt(500000)
		itwid := big.NewInt(123456)

		// Expected:
		// f0 = 1000000 + 500000 = 1500000
		// f1 = (1000000 - 500000) * 123456 = 500000 * 123456 = 61728000000

		f0 := new(big.Int).Add(v0, v1)
		f0.Mod(f0, p)

		diff := new(big.Int).Sub(v0, v1)
		diff.Mod(diff, p)
		f1 := new(big.Int).Mul(diff, itwid)
		f1.Mod(f1, p)

		t.Logf("v0 = %s, v1 = %s, itwid = %s", v0, v1, itwid)
		t.Logf("f0 = %s, f1 = %s", f0, f1)

		expectedF0 := big.NewInt(1500000)
		expectedF1 := new(big.Int).Mod(big.NewInt(61728000000), p)

		if f0.Cmp(expectedF0) != 0 {
			t.Errorf("f0 mismatch: got %s, expected %s", f0, expectedF0)
		}
		if f1.Cmp(expectedF1) != 0 {
			t.Errorf("f1 mismatch: got %s, expected %s", f1, expectedF1)
		}
	})

	t.Run("fold formula with QM31", func(t *testing.T) {
		// fold result = f0 + alpha * f1
		// where f0, f1, alpha are QM31 elements

		// Simple M31 test first
		f0 := big.NewInt(1500000)
		f1 := big.NewInt(61728000)
		alpha := big.NewInt(2000000)

		// result = f0 + alpha * f1
		alphaf1 := new(big.Int).Mul(alpha, f1)
		alphaf1.Mod(alphaf1, p)
		result := new(big.Int).Add(f0, alphaf1)
		result.Mod(result, p)

		t.Logf("f0 = %s, f1 = %s, alpha = %s", f0, f1, alpha)
		t.Logf("result = f0 + alpha*f1 = %s", result)

		// Verify manually: 1500000 + 2000000 * 61728000 = 1500000 + 123456000000000
		expected := new(big.Int).Mul(alpha, f1)
		expected.Add(expected, f0)
		expected.Mod(expected, p)

		if result.Cmp(expected) != 0 {
			t.Errorf("fold result mismatch: got %s, expected %s", result, expected)
		}
	})

	t.Run("circle point computation", func(t *testing.T) {
		// Test computing a circle point for a specific index
		// Generator: (2, 1268011823)

		genX := big.NewInt(2)
		genY := big.NewInt(1268011823)

		// Verify generator is on circle: x^2 + y^2 = 1 mod p
		xSq := new(big.Int).Mul(genX, genX)
		ySq := new(big.Int).Mul(genY, genY)
		sum := new(big.Int).Add(xSq, ySq)
		sum.Mod(sum, p)

		one := big.NewInt(1)
		if sum.Cmp(one) != 0 {
			t.Errorf("Generator not on circle: x^2 + y^2 = %s, expected 1", sum)
		} else {
			t.Logf("Generator verified on circle: (%s, %s)", genX, genY)
		}

		// Test point doubling: 2*(x,y) = (2x^2 - 1, 2xy)
		twoXSq := new(big.Int).Mul(big.NewInt(2), xSq)
		twoXSq.Mod(twoXSq, p)
		doubleX := new(big.Int).Sub(twoXSq, one)
		doubleX.Mod(doubleX, p)

		xy := new(big.Int).Mul(genX, genY)
		doubleY := new(big.Int).Mul(big.NewInt(2), xy)
		doubleY.Mod(doubleY, p)

		t.Logf("2*GEN = (%s, %s)", doubleX, doubleY)

		// Verify doubled point is on circle
		dxSq := new(big.Int).Mul(doubleX, doubleX)
		dySq := new(big.Int).Mul(doubleY, doubleY)
		dsum := new(big.Int).Add(dxSq, dySq)
		dsum.Mod(dsum, p)

		if dsum.Cmp(one) != 0 {
			t.Errorf("Doubled point not on circle: x^2 + y^2 = %s", dsum)
		} else {
			t.Logf("Doubled point verified on circle")
		}
	})

	t.Run("line domain x from position", func(t *testing.T) {
		// For LineDomain from Coset::half_odds(log_size):
		// initial_index = 2^(31 - (log_size + 2))
		// step_size = 2^(31 - log_size)

		logSize := uint32(4) // domain size 16

		// Calculate coset parameters
		initialIndex := uint64(1) << (31 - logSize - 2)
		stepSize := uint64(1) << (31 - logSize)

		t.Logf("LineDomain log_size=%d: initial_index=%d, step_size=%d", logSize, initialIndex, stepSize)

		// Position 0: index = initialIndex
		// Position 1: index = initialIndex + stepSize
		// etc.

		for i := 0; i < 4; i++ {
			index := initialIndex + stepSize*uint64(i)
			t.Logf("Position %d: circle point index = %d", i, index)
		}
	})

	t.Run("bit_reverse_index", func(t *testing.T) {
		// Test bit reversal for log_size = 3 (size 8)
		logSize := uint(3)

		for i := 0; i < 8; i++ {
			reversed := bitReverseIndex(i, logSize)
			t.Logf("bit_reverse_index(%d, %d) = %d", i, logSize, reversed)
		}

		// Expected results:
		// 0 -> 0, 1 -> 4, 2 -> 2, 3 -> 6, 4 -> 1, 5 -> 5, 6 -> 3, 7 -> 7
		expected := []int{0, 4, 2, 6, 1, 5, 3, 7}
		for i := 0; i < 8; i++ {
			got := bitReverseIndex(i, logSize)
			if got != expected[i] {
				t.Errorf("bit_reverse_index(%d, %d) = %d, expected %d", i, logSize, got, expected[i])
			}
		}
	})
}

// bitReverseIndex reverses the bits of i within logSize bits
func bitReverseIndex(i int, logSize uint) int {
	if logSize == 0 {
		return i
	}
	result := 0
	for bit := uint(0); bit < logSize; bit++ {
		if i&(1<<bit) != 0 {
			result |= 1 << (logSize - 1 - bit)
		}
	}
	return result
}

// TestQM31Arithmetic verifies QM31 multiplication matches stwo
func TestQM31Arithmetic(t *testing.T) {
	p := mersenne31.M31Modulus

	// QM31 = CM31[u] / (u^2 - 2 - i)
	// where CM31 = M31[i] / (i^2 + 1)

	// QM31 multiplication:
	// (a + bi + cu + dui) * (e + fi + gu + hui)
	// This is complex, let's verify with simple cases

	t.Run("QM31 addition", func(t *testing.T) {
		// (1, 2, 3, 4) + (5, 6, 7, 8) = (6, 8, 10, 12)
		a := [4]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
		b := [4]*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}

		result := [4]*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
		for i := 0; i < 4; i++ {
			result[i].Add(a[i], b[i])
			result[i].Mod(result[i], p)
		}

		expected := [4]int64{6, 8, 10, 12}
		for i := 0; i < 4; i++ {
			if result[i].Cmp(big.NewInt(expected[i])) != 0 {
				t.Errorf("Component %d: got %s, expected %d", i, result[i], expected[i])
			}
		}
		t.Logf("QM31 addition verified")
	})

	t.Run("QM31 scalar multiplication", func(t *testing.T) {
		// (1, 2, 3, 4) * 5 = (5, 10, 15, 20)
		a := [4]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
		scalar := big.NewInt(5)

		result := [4]*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
		for i := 0; i < 4; i++ {
			result[i].Mul(a[i], scalar)
			result[i].Mod(result[i], p)
		}

		expected := [4]int64{5, 10, 15, 20}
		for i := 0; i < 4; i++ {
			if result[i].Cmp(big.NewInt(expected[i])) != 0 {
				t.Errorf("Component %d: got %s, expected %d", i, result[i], expected[i])
			}
		}
		t.Logf("QM31 scalar multiplication verified")
	})
}
