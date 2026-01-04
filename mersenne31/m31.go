// Package mersenne31 implements field arithmetic for M31 (Mersenne-31),
// CM31 (complex extension), and QM31 (quartic extension) in gnark circuits.
//
// M31 is the Mersenne prime field with modulus p = 2^31 - 1 = 0x7FFFFFFF.
// This field is used in stwo's Circle STARK implementation.
package mersenne31

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// M31 field constants
var (
	// Modulus p = 2^31 - 1
	M31Modulus = new(big.Int).SetUint64(0x7FFFFFFF)

	// Modulus - 1 (maximum valid field element)
	M31ModulusSub1 = new(big.Int).SetUint64(0x7FFFFFFE)

	// 2^31 for reduction
	TwoTo31 = new(big.Int).SetUint64(1 << 31)

	// 2^27 for limb decomposition
	TwoTo27 = new(big.Int).SetUint64(1 << 27)

	// Maximum upper bound before we must reduce (2^120)
	MaxUpperBound = new(big.Int).Lsh(big.NewInt(1), 120)
)

func init() {
	// Register hints for gnark's solver
	solver.RegisterHint(ReduceM31Hint)
	solver.RegisterHint(InvM31Hint)
	solver.RegisterHint(SplitLimbsM31Hint)
}

// M31Variable represents an M31 field element in a gnark circuit.
// It tracks an upper bound to enable delayed reduction optimization.
type M31Variable struct {
	Value      frontend.Variable
	UpperBound *big.Int
}

// M31Chip provides M31 field operations in gnark circuits.
type M31Chip struct {
	api          frontend.API
	RangeChecker frontend.Rangechecker
	isGroth16    bool
}

// NewM31Chip creates a new M31Chip for the given gnark API.
func NewM31Chip(api frontend.API, isGroth16 bool) *M31Chip {
	return &M31Chip{
		api:          api,
		RangeChecker: rangecheck.New(api),
		isGroth16:    isGroth16,
	}
}

// Zero returns the zero element of M31.
func Zero() M31Variable {
	return M31Variable{
		Value:      frontend.Variable("0"),
		UpperBound: new(big.Int).SetUint64(0),
	}
}

// One returns the one element of M31.
func One() M31Variable {
	return M31Variable{
		Value:      frontend.Variable("1"),
		UpperBound: new(big.Int).SetUint64(1),
	}
}

// NewM31Const creates a constant M31Variable with a known value.
func NewM31Const(value string) M31Variable {
	intValue, success := new(big.Int).SetString(value, 10)
	if !success {
		panic("invalid M31 constant: " + value)
	}
	return M31Variable{
		Value:      frontend.Variable(value),
		UpperBound: intValue,
	}
}

// AddM31 computes a + b in M31.
// Uses delayed reduction: only reduces when upper bound approaches overflow.
func (c *M31Chip) AddM31(a, b M31Variable) M31Variable {
	result := M31Variable{
		Value:      c.api.Add(a.Value, b.Value),
		UpperBound: new(big.Int).Add(a.UpperBound, b.UpperBound),
	}
	return c.reduceFast(result)
}

// AddM31NoReduce computes a + b without reduction.
// Use when you know the result will be reduced later.
func (c *M31Chip) AddM31NoReduce(a, b M31Variable) M31Variable {
	return M31Variable{
		Value:      c.api.Add(a.Value, b.Value),
		UpperBound: new(big.Int).Add(a.UpperBound, b.UpperBound),
	}
}

// SubM31 computes a - b in M31.
func (c *M31Chip) SubM31(a, b M31Variable) M31Variable {
	negB := c.NegM31(b)
	return c.AddM31(a, negB)
}

// NegM31 computes -a in M31.
func (c *M31Chip) NegM31(a M31Variable) M31Variable {
	// Compute the smallest multiple of p that is >= a.UpperBound
	divisor := new(big.Int).Div(a.UpperBound, M31Modulus)
	divisorPlusOne := new(big.Int).Add(divisor, big.NewInt(1))
	liftedModulus := new(big.Int).Mul(divisorPlusOne, M31Modulus)

	return c.reduceFast(M31Variable{
		Value:      c.api.Sub(liftedModulus, a.Value),
		UpperBound: liftedModulus,
	})
}

// MulM31 computes a * b in M31.
func (c *M31Chip) MulM31(a, b M31Variable) M31Variable {
	result := M31Variable{
		Value:      c.api.Mul(a.Value, b.Value),
		UpperBound: new(big.Int).Mul(a.UpperBound, b.UpperBound),
	}
	return c.reduceFast(result)
}

// MulM31NoReduce computes a * b without reduction.
func (c *M31Chip) MulM31NoReduce(a, b M31Variable) M31Variable {
	return M31Variable{
		Value:      c.api.Mul(a.Value, b.Value),
		UpperBound: new(big.Int).Mul(a.UpperBound, b.UpperBound),
	}
}

// MulM31Const computes a * constant in M31.
func (c *M31Chip) MulM31Const(a M31Variable, constant int) M31Variable {
	result := M31Variable{
		Value:      c.api.Mul(a.Value, constant),
		UpperBound: new(big.Int).Mul(a.UpperBound, big.NewInt(int64(constant))),
	}
	return c.reduceFast(result)
}

// InvM31 computes the multiplicative inverse of a in M31.
// Uses a hint to compute the inverse, then verifies a * a^{-1} = 1.
func (c *M31Chip) InvM31(a M31Variable) M31Variable {
	result, err := c.api.Compiler().NewHint(InvM31Hint, 1, a.Value)
	if err != nil {
		panic(err)
	}

	aInv := M31Variable{
		Value:      result[0],
		UpperBound: new(big.Int).Set(M31Modulus),
	}

	// Range check the inverse
	c.rangeCheck31(result[0])

	// Verify: a * aInv = 1 (mod p)
	product := c.MulM31(a, aInv)
	c.AssertEqM31(product, One())

	return aInv
}

// AssertEqM31 asserts that a == b in M31.
func (c *M31Chip) AssertEqM31(a, b M31Variable) {
	aReduced := c.ReduceSlow(a)
	bReduced := c.ReduceSlow(b)
	c.api.AssertIsEqual(aReduced.Value, bReduced.Value)
}

// SelectM31 returns a if cond is true, else b.
func (c *M31Chip) SelectM31(cond frontend.Variable, a, b M31Variable) M31Variable {
	var upperBound *big.Int
	if a.UpperBound.Cmp(b.UpperBound) >= 0 {
		upperBound = a.UpperBound
	} else {
		upperBound = b.UpperBound
	}
	return M31Variable{
		Value:      c.api.Select(cond, a.Value, b.Value),
		UpperBound: upperBound,
	}
}

// reduceFast reduces x modulo p only if the upper bound is approaching overflow.
// This is the key optimization: we delay reductions as long as possible.
func (c *M31Chip) reduceFast(x M31Variable) M31Variable {
	if x.UpperBound.BitLen() >= 120 {
		return M31Variable{
			Value:      c.reduceWithMaxBits(x.Value, uint64(x.UpperBound.BitLen())),
			UpperBound: new(big.Int).Set(M31ModulusSub1),
		}
	}
	return x
}

// ReduceSlow performs full modular reduction, ensuring the result is in [0, p-1].
func (c *M31Chip) ReduceSlow(x M31Variable) M31Variable {
	if x.UpperBound.Cmp(M31Modulus) < 0 {
		return x
	}
	return M31Variable{
		Value:      c.reduceWithMaxBits(x.Value, uint64(x.UpperBound.BitLen())),
		UpperBound: new(big.Int).Set(M31ModulusSub1),
	}
}

// reduceWithMaxBits performs modular reduction using a hint.
// It decomposes x = q * p + r where r < p.
func (c *M31Chip) reduceWithMaxBits(x frontend.Variable, maxNbBits uint64) frontend.Variable {
	if maxNbBits <= 30 {
		return x
	}

	// Use hint to get quotient and remainder
	result, err := c.api.Compiler().NewHint(ReduceM31Hint, 2, x)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	remainder := result[1]

	// Range check the quotient
	quotientBits := int(maxNbBits - 30)
	if quotientBits > 0 {
		c.rangeCheckN(quotient, quotientBits)
	}

	// Verify remainder is in valid M31 range using limb decomposition
	c.verifyM31Range(remainder)

	// Verify: x = quotient * p + remainder
	c.api.AssertIsEqual(x, c.api.Add(c.api.Mul(quotient, M31Modulus), remainder))

	return remainder
}

// verifyM31Range verifies that a value is a valid M31 element (< p = 2^31 - 1).
// We decompose into a 27-bit low limb and a 4-bit high limb.
// We reject only the case where x = p = 2^31 - 1 exactly.
func (c *M31Chip) verifyM31Range(x frontend.Variable) {
	// Use hint to split into limbs
	limbs, err := c.api.Compiler().NewHint(SplitLimbsM31Hint, 2, x)
	if err != nil {
		panic(err)
	}

	lowLimb := limbs[0]  // 27 bits
	highLimb := limbs[1] // 4 bits

	// Verify the decomposition: x = highLimb * 2^27 + lowLimb
	c.api.AssertIsEqual(
		c.api.Add(c.api.Mul(highLimb, TwoTo27), lowLimb),
		x,
	)

	// Range check both limbs
	c.rangeCheckN(highLimb, 4)
	c.rangeCheckN(lowLimb, 27)

	// We need x < p = 2^31 - 1
	// x = highLimb * 2^27 + lowLimb
	// If highLimb < 15, then x < 15 * 2^27 < 2^31 - 1 (always valid)
	// If highLimb = 15, then x = 15 * 2^27 + lowLimb
	//   - lowLimb can be [0, 2^27 - 1]
	//   - x would be [2013265920, 2147483647]
	//   - We need x < 2147483647 = p
	//   - So we reject only when highLimb = 15 AND lowLimb = 2^27 - 1
	//
	// TwoTo27 - 1 = 134217727 = 2^27 - 1
	twoTo27Minus1 := c.api.Sub(TwoTo27, 1)

	// Check if highLimb == 15 AND lowLimb == 2^27 - 1
	highIs15 := c.api.IsZero(c.api.Sub(highLimb, 15))
	lowIsMax := c.api.IsZero(c.api.Sub(lowLimb, twoTo27Minus1))

	// Reject if both conditions are true (would mean x = p)
	bothTrue := c.api.Mul(highIs15, lowIsMax)
	c.api.AssertIsEqual(bothTrue, frontend.Variable(0))
}

// rangeCheck31 range checks that x is a valid 31-bit value.
func (c *M31Chip) rangeCheck31(x frontend.Variable) {
	c.rangeCheckN(x, 31)
}

// rangeCheckN range checks that x fits in n bits.
func (c *M31Chip) rangeCheckN(x frontend.Variable, n int) {
	if c.isGroth16 {
		// For Groth16, use ToBinary which is more efficient
		c.api.ToBinary(x, n)
	} else {
		// For PLONK, use the range checker gadget
		c.RangeChecker.Check(x, n)
	}
}

// API returns the underlying gnark API.
func (c *M31Chip) API() frontend.API {
	return c.api
}

// M31ToQM31 lifts an M31 element to QM31 (embeds in the first component).
func (c *M31Chip) M31ToQM31(x M31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			x,
			Zero(),
			Zero(),
			Zero(),
		},
	}
}

// ReduceM31Hint computes x mod p = 2^31 - 1.
// Returns [quotient, remainder].
func ReduceM31Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("ReduceM31Hint expects 1 input, got %d", len(inputs))
	}
	x := inputs[0]
	quotient := new(big.Int).Div(x, M31Modulus)
	remainder := new(big.Int).Mod(x, M31Modulus)
	results[0] = quotient
	results[1] = remainder
	return nil
}

// SplitLimbsM31Hint splits an M31 element into a 27-bit low limb and 4-bit high limb.
// Returns [lowLimb, highLimb].
func SplitLimbsM31Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("SplitLimbsM31Hint expects 1 input, got %d", len(inputs))
	}
	x := inputs[0]

	// x should be < p = 2^31 - 1
	if x.Cmp(M31Modulus) >= 0 {
		return fmt.Errorf("SplitLimbsM31Hint: input %s is not a valid M31 element (>= %s)", x.String(), M31Modulus.String())
	}

	lowLimb := new(big.Int).And(x, new(big.Int).Sub(TwoTo27, big.NewInt(1)))
	highLimb := new(big.Int).Rsh(x, 27)

	results[0] = lowLimb
	results[1] = highLimb
	return nil
}

// InvM31Hint computes the modular inverse of x in M31.
// Uses Fermat's little theorem: x^{-1} = x^{p-2} mod p.
func InvM31Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("InvM31Hint expects 1 input, got %d", len(inputs))
	}
	x := new(big.Int).Mod(inputs[0], M31Modulus)
	if x.Sign() == 0 {
		return fmt.Errorf("InvM31Hint: cannot invert zero")
	}

	// x^{-1} = x^{p-2} mod p
	pMinus2 := new(big.Int).Sub(M31Modulus, big.NewInt(2))
	results[0] = new(big.Int).Exp(x, pMinus2, M31Modulus)
	return nil
}
