// QM31 implements the quartic extension field QM31 = CM31[u] / (u^2 - (2 + i)).
// Elements are represented as (a + bi) + (c + di)u where a, b, c, d are M31 elements.
// This is equivalent to [a, b, c, d] where the element is a + bi + cu + diu.
package mersenne31

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() {
	solver.RegisterHint(InvQM31Hint)
}

// QM31Variable represents a QM31 field element in a gnark circuit.
// Stored as [a, b, c, d] representing (a + bi) + (c + di)u.
type QM31Variable struct {
	Value [4]M31Variable
}

// ZeroQM31 returns the zero element of QM31.
func ZeroQM31() QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{Zero(), Zero(), Zero(), Zero()},
	}
}

// OneQM31 returns the one element of QM31.
func OneQM31() QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{One(), Zero(), Zero(), Zero()},
	}
}

// NewQM31Const creates a constant QM31Variable.
func NewQM31Const(a, b, c, d string) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			NewM31Const(a),
			NewM31Const(b),
			NewM31Const(c),
			NewM31Const(d),
		},
	}
}

// NewQM31 creates a QM31Variable from witness values.
func NewQM31(a, b, c, d string) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			NewM31(a),
			NewM31(b),
			NewM31(c),
			NewM31(d),
		},
	}
}

// NewQM31FromArray creates a QM31Variable from an array of strings.
func NewQM31FromArray(values []string) QM31Variable {
	if len(values) != 4 {
		panic("QM31 requires exactly 4 values")
	}
	return NewQM31(values[0], values[1], values[2], values[3])
}

// NewQM31FromM31 creates a QM31Variable from four M31Variables.
func NewQM31FromM31(a, b, c, d M31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{a, b, c, d},
	}
}

// NewQM31FromCM31 creates a QM31Variable from two CM31Variables.
// QM31 = CM31 + CM31 * u
func NewQM31FromCM31(first, second CM31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{first.Real, first.Imag, second.Real, second.Imag},
	}
}

// First returns the first CM31 component (a + bi).
func (q QM31Variable) First() CM31Variable {
	return CM31Variable{
		Real: q.Value[0],
		Imag: q.Value[1],
	}
}

// Second returns the second CM31 component (c + di).
func (q QM31Variable) Second() CM31Variable {
	return CM31Variable{
		Real: q.Value[2],
		Imag: q.Value[3],
	}
}

// AddQM31 computes a + b in QM31.
func (c *M31Chip) AddQM31(a, b QM31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.AddM31(a.Value[0], b.Value[0]),
			c.AddM31(a.Value[1], b.Value[1]),
			c.AddM31(a.Value[2], b.Value[2]),
			c.AddM31(a.Value[3], b.Value[3]),
		},
	}
}

// AddQM31NoReduce computes a + b without reduction.
func (c *M31Chip) AddQM31NoReduce(a, b QM31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.AddM31NoReduce(a.Value[0], b.Value[0]),
			c.AddM31NoReduce(a.Value[1], b.Value[1]),
			c.AddM31NoReduce(a.Value[2], b.Value[2]),
			c.AddM31NoReduce(a.Value[3], b.Value[3]),
		},
	}
}

// SubQM31 computes a - b in QM31.
func (c *M31Chip) SubQM31(a, b QM31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.SubM31(a.Value[0], b.Value[0]),
			c.SubM31(a.Value[1], b.Value[1]),
			c.SubM31(a.Value[2], b.Value[2]),
			c.SubM31(a.Value[3], b.Value[3]),
		},
	}
}

// NegQM31 computes -a in QM31.
func (c *M31Chip) NegQM31(a QM31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.NegM31(a.Value[0]),
			c.NegM31(a.Value[1]),
			c.NegM31(a.Value[2]),
			c.NegM31(a.Value[3]),
		},
	}
}

// MulQM31 computes a * b in QM31.
// (a0 + a1*u) * (b0 + b1*u) = a0*b0 + (a0*b1 + a1*b0)*u + a1*b1*u^2
// Since u^2 = 2 + i, we have:
// = a0*b0 + a1*b1*(2+i) + (a0*b1 + a1*b0)*u
// = (a0*b0 + 2*a1*b1 + i*a1*b1) + (a0*b1 + a1*b0)*u
func (c *M31Chip) MulQM31(a, b QM31Variable) QM31Variable {
	// Get CM31 components
	a0 := a.First()  // a[0] + a[1]*i
	a1 := a.Second() // a[2] + a[3]*i
	b0 := b.First()  // b[0] + b[1]*i
	b1 := b.Second() // b[2] + b[3]*i

	// Compute products
	a0b0 := c.MulCM31(a0, b0) // CM31
	a0b1 := c.MulCM31(a0, b1) // CM31
	a1b0 := c.MulCM31(a1, b0) // CM31
	a1b1 := c.MulCM31(a1, b1) // CM31

	// Multiply a1b1 by (2 + i)
	// (x + yi) * (2 + i) = (2x - y) + (x + 2y)i
	a1b1Times2PlusI := c.mulCM31By2PlusI(a1b1)

	// First CM31 component: a0*b0 + a1*b1*(2+i)
	first := c.AddCM31(a0b0, a1b1Times2PlusI)

	// Second CM31 component: a0*b1 + a1*b0
	second := c.AddCM31(a0b1, a1b0)

	return NewQM31FromCM31(first, second)
}

// mulCM31By2PlusI computes x * (2 + i) where x is CM31.
// (a + bi) * (2 + i) = (2a - b) + (a + 2b)i
func (c *M31Chip) mulCM31By2PlusI(x CM31Variable) CM31Variable {
	// 2a
	twoA := c.MulM31Const(x.Real, 2)
	// 2b
	twoB := c.MulM31Const(x.Imag, 2)

	// Real: 2a - b
	real := c.SubM31(twoA, x.Imag)
	// Imag: a + 2b
	imag := c.AddM31(x.Real, twoB)

	return CM31Variable{Real: real, Imag: imag}
}

// MulQM31ByM31 computes a * b where a is QM31 and b is M31.
func (c *M31Chip) MulQM31ByM31(a QM31Variable, b M31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.MulM31(a.Value[0], b),
			c.MulM31(a.Value[1], b),
			c.MulM31(a.Value[2], b),
			c.MulM31(a.Value[3], b),
		},
	}
}

// MulQM31ByCM31 computes a * b where a is QM31 and b is CM31.
func (c *M31Chip) MulQM31ByCM31(a QM31Variable, b CM31Variable) QM31Variable {
	first := c.MulCM31(a.First(), b)
	second := c.MulCM31(a.Second(), b)
	return NewQM31FromCM31(first, second)
}

// AddQM31ByM31 computes a + b where a is QM31 and b is M31.
func (c *M31Chip) AddQM31ByM31(a QM31Variable, b M31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.AddM31(a.Value[0], b),
			a.Value[1],
			a.Value[2],
			a.Value[3],
		},
	}
}

// SubQM31ByM31 computes a - b where a is QM31 and b is M31.
func (c *M31Chip) SubQM31ByM31(a QM31Variable, b M31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.SubM31(a.Value[0], b),
			a.Value[1],
			a.Value[2],
			a.Value[3],
		},
	}
}

// ComplexConjugate computes the complex conjugate of a QM31 element.
// For (a + bi) + (c + di)u, the conjugate is (a - bi) + (c - di)u.
func (c *M31Chip) ComplexConjugate(a QM31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			a.Value[0],
			c.NegM31(a.Value[1]),
			a.Value[2],
			c.NegM31(a.Value[3]),
		},
	}
}

// InvQM31 computes the multiplicative inverse of a in QM31.
func (c *M31Chip) InvQM31(a QM31Variable) QM31Variable {
	// Use hint to compute the inverse
	result, err := c.api.Compiler().NewHint(
		InvQM31Hint, 4,
		a.Value[0].Value, a.Value[1].Value, a.Value[2].Value, a.Value[3].Value,
	)
	if err != nil {
		panic(err)
	}

	aInv := QM31Variable{
		Value: [4]M31Variable{
			{Value: result[0], UpperBound: new(big.Int).Set(M31Modulus)},
			{Value: result[1], UpperBound: new(big.Int).Set(M31Modulus)},
			{Value: result[2], UpperBound: new(big.Int).Set(M31Modulus)},
			{Value: result[3], UpperBound: new(big.Int).Set(M31Modulus)},
		},
	}

	// Range check all components
	for i := 0; i < 4; i++ {
		c.rangeCheck31(result[i])
	}

	// Verify: a * aInv = 1
	product := c.MulQM31(a, aInv)
	c.AssertEqQM31(product, OneQM31())

	return aInv
}

// DivQM31 computes a / b in QM31.
func (c *M31Chip) DivQM31(a, b QM31Variable) QM31Variable {
	bInv := c.InvQM31(b)
	return c.MulQM31(a, bInv)
}

// DivQM31ByM31 computes a / b where a is QM31 and b is M31.
func (c *M31Chip) DivQM31ByM31(a QM31Variable, b M31Variable) QM31Variable {
	bInv := c.InvM31(b)
	return c.MulQM31ByM31(a, bInv)
}

// AssertEqQM31 asserts that a == b in QM31.
func (c *M31Chip) AssertEqQM31(a, b QM31Variable) {
	for i := 0; i < 4; i++ {
		c.AssertEqM31(a.Value[i], b.Value[i])
	}
}

// SelectQM31 returns a if cond is true, else b.
func (c *M31Chip) SelectQM31(cond frontend.Variable, a, b QM31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.SelectM31(cond, a.Value[0], b.Value[0]),
			c.SelectM31(cond, a.Value[1], b.Value[1]),
			c.SelectM31(cond, a.Value[2], b.Value[2]),
			c.SelectM31(cond, a.Value[3], b.Value[3]),
		},
	}
}

// ReduceSlowQM31 performs full modular reduction on all components.
func (c *M31Chip) ReduceSlowQM31(a QM31Variable) QM31Variable {
	return QM31Variable{
		Value: [4]M31Variable{
			c.ReduceSlow(a.Value[0]),
			c.ReduceSlow(a.Value[1]),
			c.ReduceSlow(a.Value[2]),
			c.ReduceSlow(a.Value[3]),
		},
	}
}

// Ext2Felt converts a QM31 to its four M31 components.
func (c *M31Chip) Ext2Felt(a QM31Variable) [4]M31Variable {
	return a.Value
}

// FromPartialEvals reconstructs a QM31 from four partial evaluations.
// This is used in FRI folding.
// Given evaluations [f(P), f(-P), f(iP), f(-iP)], reconstructs the original polynomial value.
func (c *M31Chip) FromPartialEvals(evals [4]QM31Variable) QM31Variable {
	// The formula for reconstruction from the stwo verifier:
	// Let e0, e1, e2, e3 be the four evaluations
	// a = (e0 + e1) / 2
	// b = (e0 - e1) / 2
	// c = (e2 + e3) / 2
	// d = (e2 - e3) / 2
	// Result depends on the specific point configuration

	// For now, return a simple implementation
	// The actual formula depends on the evaluation point structure
	// This will need to be refined based on stwo's specific partial eval structure

	// Simplified version - actual implementation needs stwo-specific formula
	sum := c.AddQM31(evals[0], evals[1])
	sum = c.AddQM31(sum, evals[2])
	sum = c.AddQM31(sum, evals[3])

	// Divide by 4 (multiply by inverse of 4)
	four := NewM31Const("4")
	fourInv := c.InvM31(four)
	return c.MulQM31ByM31(sum, fourInv)
}

// InvQM31Hint computes the inverse of a QM31 element.
func InvQM31Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 4 {
		panic("InvQM31Hint expects 4 inputs")
	}

	// Get the four M31 components
	a := new(big.Int).Mod(inputs[0], M31Modulus)
	b := new(big.Int).Mod(inputs[1], M31Modulus)
	c := new(big.Int).Mod(inputs[2], M31Modulus)
	d := new(big.Int).Mod(inputs[3], M31Modulus)

	// QM31 = CM31[u] / (u^2 - (2+i))
	// For x = (a+bi) + (c+di)u, we compute x^{-1}
	// Using the formula: x^{-1} = conj(x) / norm(x)
	// where norm is computed using the extension structure

	// First, compute the norm in CM31:
	// For x = x0 + x1*u where x0, x1 are CM31
	// norm(x) = x0^2 - x1^2 * (2+i) in CM31

	// x0 = a + bi, x1 = c + di
	// x0^2 = (a+bi)^2 = (a^2-b^2) + 2abi
	// x1^2 = (c+di)^2 = (c^2-d^2) + 2cdi
	// x1^2 * (2+i) = ((c^2-d^2) + 2cdi) * (2+i)
	//              = (2(c^2-d^2) - 2cd) + ((c^2-d^2) + 4cd)i

	// Compute x0^2 = (a^2 - b^2) + 2ab*i
	aSq := mulMod(a, a)
	bSq := mulMod(b, b)
	x0SqReal := subMod(aSq, bSq)
	x0SqImag := mulMod(mulMod(big.NewInt(2), a), b)

	// Compute x1^2 = (c^2 - d^2) + 2cd*i
	cSq := mulMod(c, c)
	dSq := mulMod(d, d)
	x1SqReal := subMod(cSq, dSq)
	x1SqImag := mulMod(mulMod(big.NewInt(2), c), d)

	// Compute x1^2 * (2+i) = (2*real - imag) + (real + 2*imag)*i
	x1Sq2piReal := subMod(mulMod(big.NewInt(2), x1SqReal), x1SqImag)
	x1Sq2piImag := addMod(x1SqReal, mulMod(big.NewInt(2), x1SqImag))

	// Compute norm = x0^2 - x1^2 * (2+i) in CM31
	normReal := subMod(x0SqReal, x1Sq2piReal)
	normImag := subMod(x0SqImag, x1Sq2piImag)

	// Compute norm^{-1} in CM31
	// (r + si)^{-1} = (r - si) / (r^2 + s^2)
	normNormSq := addMod(mulMod(normReal, normReal), mulMod(normImag, normImag))
	normNormSqInv := invMod(normNormSq)

	normInvReal := mulMod(normReal, normNormSqInv)
	normInvImag := subMod(big.NewInt(0), mulMod(normImag, normNormSqInv))

	// x^{-1} = (x0 - x1*u) * norm^{-1} / (some factor depending on extension)
	// Actually: x^{-1} = conj(x) * norm^{-1} where conj swaps sign of u coefficient
	// x^{-1} = (x0 - x1*u) * norm^{-1}
	// = x0 * norm^{-1} - x1 * norm^{-1} * u

	// Compute x0 * norm^{-1} in CM31
	// (a+bi) * (r+si) = (ar - bs) + (as + br)i
	resFirstReal := subMod(mulMod(a, normInvReal), mulMod(b, normInvImag))
	resFirstImag := addMod(mulMod(a, normInvImag), mulMod(b, normInvReal))

	// Compute -x1 * norm^{-1} in CM31 (the u coefficient)
	negC := subMod(big.NewInt(0), c)
	negD := subMod(big.NewInt(0), d)
	resSecondReal := subMod(mulMod(negC, normInvReal), mulMod(negD, normInvImag))
	resSecondImag := addMod(mulMod(negC, normInvImag), mulMod(negD, normInvReal))

	results[0] = resFirstReal
	results[1] = resFirstImag
	results[2] = resSecondReal
	results[3] = resSecondImag

	return nil
}

// Helper functions for modular arithmetic in hints
func addMod(a, b *big.Int) *big.Int {
	result := new(big.Int).Add(a, b)
	return result.Mod(result, M31Modulus)
}

func subMod(a, b *big.Int) *big.Int {
	result := new(big.Int).Sub(a, b)
	return result.Mod(result, M31Modulus)
}

func mulMod(a, b *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	return result.Mod(result, M31Modulus)
}

func invMod(a *big.Int) *big.Int {
	if a.Sign() == 0 {
		panic("cannot invert zero")
	}
	pMinus2 := new(big.Int).Sub(M31Modulus, big.NewInt(2))
	return new(big.Int).Exp(a, pMinus2, M31Modulus)
}

// FusedQuotientDenominator computes the denominator for two-point quotienting.
// Given sample point P=(px, py) in QM31 and domain point D=(dx, dy) in M31,
// computes: Im((px - dx).conj() * (py - dy))
// The result is in CM31, which is the second component of the QM31 product.
//
// Formula: (Pr.x - D.x) * Pi.y - (Pr.y - D.y) * Px.i
// where Pr, Pi are the real and imaginary parts of P (both CM31).
func (c *M31Chip) FusedQuotientDenominator(px, py QM31Variable, dx, dy M31Variable) CM31Variable {
	// Extract CM31 components of px and py
	// QM31 = (a + bi) + (c + di)u where a,b is the real part and c,d is the imaginary part
	pxReal := px.First()  // CM31: (px[0], px[1])
	pxImag := px.Second() // CM31: (px[2], px[3])
	pyReal := py.First()  // CM31: (py[0], py[1])
	pyImag := py.Second() // CM31: (py[2], py[3])

	// Compute (px - dx): subtract M31 from the real part of real CM31
	pxMinusDxReal := CM31Variable{
		Real: c.SubM31(pxReal.Real, dx),
		Imag: pxReal.Imag,
	}
	pxMinusDxImag := pxImag

	// Compute (py - dy): subtract M31 from the real part of real CM31
	pyMinusDyReal := CM31Variable{
		Real: c.SubM31(pyReal.Real, dy),
		Imag: pyReal.Imag,
	}
	pyMinusDyImag := pyImag

	// The formula is: (px - dx).conj() * (py - dy)
	// For QM31 = r + i*u, conj() = r - i*u
	// So (px-dx).conj() = pxMinusDxReal - pxMinusDxImag*u
	//
	// ((a) + (b)*u).conj() * ((c) + (d)*u)
	// = (a - b*u) * (c + d*u)
	// = a*c - b*d*(u^2) + (a*d - b*c)*u
	// Since u^2 = 2+i:
	// = a*c - b*d*(2+i) + (a*d - b*c)*u
	// = (a*c - 2*b*d - i*b*d) + (a*d - b*c)*u
	//
	// We want the imaginary part (the u coefficient): a*d - b*c
	// where a = pxMinusDxReal, b = pxMinusDxImag, c = pyMinusDyReal, d = pyMinusDyImag

	// Compute a*d = pxMinusDxReal * pyMinusDyImag (CM31 * CM31)
	ad := c.MulCM31(pxMinusDxReal, pyMinusDyImag)

	// Compute b*c = pxMinusDxImag * pyMinusDyReal (CM31 * CM31)
	bc := c.MulCM31(pxMinusDxImag, pyMinusDyReal)

	// Result = a*d - b*c
	return c.SubCM31(ad, bc)
}

// GetLineCoefficients computes the line coefficients (c, a, b) for two-point quotienting.
// The line passes through (sample_point.y, value) and (conj(sample_point.y), conj(value)).
//
// c = conj(p.y) - p.y = -2u * Im(p.y)
// a = conj(v) - v = -2u * Im(v)
// b = conj(p.y)*v - conj(v)*p.y = -2u * (Re(v)*Im(p.y) - Re(p.y)*Im(v))
//
// Returns (c, a, b) where the numerator at query point q is: c * F(q) - a * q.y - b
func (c *M31Chip) GetLineCoefficients(pointY, value QM31Variable) (cCoef, aCoef, bCoef QM31Variable) {
	// Get imaginary parts (the 'u' coefficient)
	imPointY := pointY.Second() // CM31: Im(p.y)
	imValue := value.Second()   // CM31: Im(v)

	// Get real parts
	rePointY := pointY.First() // CM31: Re(p.y)
	reValue := value.First()   // CM31: Re(v)

	// c = -2u * Im(p.y)
	// In QM31 representation, -2u means (0, 0, -2, 0) = -(0,0,2,0)
	// So c = (0, 0) + (-2*imPointY)*u
	negTwo := c.NegM31(NewM31Const("2"))
	cSecond := CM31Variable{
		Real: c.MulM31(imPointY.Real, negTwo),
		Imag: c.MulM31(imPointY.Imag, negTwo),
	}
	cCoef = NewQM31FromCM31(CM31Variable{Real: Zero(), Imag: Zero()}, cSecond)

	// a = -2u * Im(v)
	aSecond := CM31Variable{
		Real: c.MulM31(imValue.Real, negTwo),
		Imag: c.MulM31(imValue.Imag, negTwo),
	}
	aCoef = NewQM31FromCM31(CM31Variable{Real: Zero(), Imag: Zero()}, aSecond)

	// b = -2u * (Re(v)*Im(p.y) - Re(p.y)*Im(v))
	// First compute Re(v)*Im(p.y) and Re(p.y)*Im(v) (CM31 multiplications)
	reV_imPy := c.MulCM31(reValue, imPointY)
	rePy_imV := c.MulCM31(rePointY, imValue)
	diff := c.SubCM31(reV_imPy, rePy_imV)

	// Multiply by -2
	bSecond := CM31Variable{
		Real: c.MulM31(diff.Real, negTwo),
		Imag: c.MulM31(diff.Imag, negTwo),
	}
	bCoef = NewQM31FromCM31(CM31Variable{Real: Zero(), Imag: Zero()}, bSecond)

	return cCoef, aCoef, bCoef
}

// MulQM31ByCM31Elem multiplies QM31 by a CM31.
func (c *M31Chip) MulQM31ByCM31Elem(a QM31Variable, b CM31Variable) QM31Variable {
	return c.MulQM31ByCM31(a, b)
}
