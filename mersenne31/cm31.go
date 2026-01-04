// CM31 implements the complex extension field CM31 = M31[i] / (i^2 + 1).
// Elements are represented as a + bi where a, b are M31 elements.
package mersenne31

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() {
	solver.RegisterHint(InvCM31Hint)
}

// CM31Variable represents a CM31 field element (a + bi) in a gnark circuit.
type CM31Variable struct {
	Real M31Variable // a in a + bi
	Imag M31Variable // b in a + bi
}

// ZeroCM31 returns the zero element of CM31.
func ZeroCM31() CM31Variable {
	return CM31Variable{
		Real: Zero(),
		Imag: Zero(),
	}
}

// OneCM31 returns the one element of CM31.
func OneCM31() CM31Variable {
	return CM31Variable{
		Real: One(),
		Imag: Zero(),
	}
}

// AddCM31 computes a + b in CM31.
func (c *M31Chip) AddCM31(a, b CM31Variable) CM31Variable {
	return CM31Variable{
		Real: c.AddM31(a.Real, b.Real),
		Imag: c.AddM31(a.Imag, b.Imag),
	}
}

// SubCM31 computes a - b in CM31.
func (c *M31Chip) SubCM31(a, b CM31Variable) CM31Variable {
	return CM31Variable{
		Real: c.SubM31(a.Real, b.Real),
		Imag: c.SubM31(a.Imag, b.Imag),
	}
}

// MulCM31 computes a * b in CM31.
// (a + bi)(c + di) = (ac - bd) + (ad + bc)i
func (c *M31Chip) MulCM31(a, b CM31Variable) CM31Variable {
	// Compute ac and bd
	ac := c.MulM31NoReduce(a.Real, b.Real)
	bd := c.MulM31NoReduce(a.Imag, b.Imag)

	// Compute ad and bc
	ad := c.MulM31NoReduce(a.Real, b.Imag)
	bc := c.MulM31NoReduce(a.Imag, b.Real)

	// Real part: ac - bd
	// Imag part: ad + bc
	return CM31Variable{
		Real: c.SubM31(ac, bd),
		Imag: c.AddM31(ad, bc),
	}
}

// MulCM31ByM31 computes a * b where a is CM31 and b is M31.
func (c *M31Chip) MulCM31ByM31(a CM31Variable, b M31Variable) CM31Variable {
	return CM31Variable{
		Real: c.MulM31(a.Real, b),
		Imag: c.MulM31(a.Imag, b),
	}
}

// ConjCM31 computes the complex conjugate of a.
// conj(a + bi) = a - bi
func (c *M31Chip) ConjCM31(a CM31Variable) CM31Variable {
	return CM31Variable{
		Real: a.Real,
		Imag: c.NegM31(a.Imag),
	}
}

// NormSqCM31 computes the squared norm of a CM31 element.
// |a + bi|^2 = a^2 + b^2
func (c *M31Chip) NormSqCM31(a CM31Variable) M31Variable {
	aSq := c.MulM31NoReduce(a.Real, a.Real)
	bSq := c.MulM31NoReduce(a.Imag, a.Imag)
	return c.AddM31(aSq, bSq)
}

// InvCM31 computes the multiplicative inverse of a in CM31.
// (a + bi)^{-1} = (a - bi) / (a^2 + b^2)
func (c *M31Chip) InvCM31(a CM31Variable) CM31Variable {
	// Use hint to compute the inverse
	result, err := c.api.Compiler().NewHint(InvCM31Hint, 2, a.Real.Value, a.Imag.Value)
	if err != nil {
		panic(err)
	}

	aInv := CM31Variable{
		Real: M31Variable{Value: result[0], UpperBound: new(big.Int).Set(M31Modulus)},
		Imag: M31Variable{Value: result[1], UpperBound: new(big.Int).Set(M31Modulus)},
	}

	// Range check both components
	c.rangeCheck31(result[0])
	c.rangeCheck31(result[1])

	// Verify: a * aInv = 1
	product := c.MulCM31(a, aInv)
	c.AssertEqCM31(product, OneCM31())

	return aInv
}

// AssertEqCM31 asserts that a == b in CM31.
func (c *M31Chip) AssertEqCM31(a, b CM31Variable) {
	c.AssertEqM31(a.Real, b.Real)
	c.AssertEqM31(a.Imag, b.Imag)
}

// SelectCM31 returns a if cond is true, else b.
func (c *M31Chip) SelectCM31(cond frontend.Variable, a, b CM31Variable) CM31Variable {
	return CM31Variable{
		Real: c.SelectM31(cond, a.Real, b.Real),
		Imag: c.SelectM31(cond, a.Imag, b.Imag),
	}
}

// ReduceSlowCM31 performs full modular reduction on both components.
func (c *M31Chip) ReduceSlowCM31(a CM31Variable) CM31Variable {
	return CM31Variable{
		Real: c.ReduceSlow(a.Real),
		Imag: c.ReduceSlow(a.Imag),
	}
}

// InvCM31Hint computes the inverse of a CM31 element.
// (a + bi)^{-1} = (a - bi) / (a^2 + b^2)
func InvCM31Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("InvCM31Hint expects 2 inputs, got %d", len(inputs))
	}

	a := new(big.Int).Mod(inputs[0], M31Modulus)
	b := new(big.Int).Mod(inputs[1], M31Modulus)

	// Compute norm squared: a^2 + b^2
	aSq := new(big.Int).Mul(a, a)
	bSq := new(big.Int).Mul(b, b)
	normSq := new(big.Int).Add(aSq, bSq)
	normSq.Mod(normSq, M31Modulus)

	if normSq.Sign() == 0 {
		return fmt.Errorf("InvCM31Hint: cannot invert zero CM31 element (a=%s, b=%s)", a.String(), b.String())
	}

	// Compute normSq^{-1} = normSq^{p-2} mod p
	pMinus2 := new(big.Int).Sub(M31Modulus, big.NewInt(2))
	normSqInv := new(big.Int).Exp(normSq, pMinus2, M31Modulus)

	// (a + bi)^{-1} = (a - bi) / normSq = (a * normSqInv) - (b * normSqInv) * i
	realPart := new(big.Int).Mul(a, normSqInv)
	realPart.Mod(realPart, M31Modulus)

	// For imaginary part, we need -b * normSqInv
	imagPart := new(big.Int).Mul(b, normSqInv)
	imagPart.Mod(imagPart, M31Modulus)
	// Negate: -x mod p = p - x (if x != 0)
	if imagPart.Sign() != 0 {
		imagPart.Sub(M31Modulus, imagPart)
	}

	results[0] = realPart
	results[1] = imagPart
	return nil
}
