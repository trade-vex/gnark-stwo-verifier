// Package circle implements circle group operations for Circle STARKs.
// The circle group is defined by the equation x^2 + y^2 = 1 over the M31 field.
package circle

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/gnark-stwo/stwo/mersenne31"
)

func init() {
	solver.RegisterHint(IndexToPointHint)
}

// M31 Circle group constants
var (
	// M31_CIRCLE_GEN is the generator of the M31 circle group.
	// This point has order 2^31 (the full circle group order).
	M31CircleGenX = uint32(2)
	M31CircleGenY = uint32(0x4B94532F) // 1268011823

	// Log of the circle group order
	M31CircleLogOrder = uint32(31)
)

// CirclePointM31 represents a point on the circle x^2 + y^2 = 1 over M31.
type CirclePointM31 struct {
	X mersenne31.M31Variable
	Y mersenne31.M31Variable
}

// CirclePointQM31 represents a point on the circle over QM31 extension field.
// Used for out-of-domain (OOD) sampling points.
type CirclePointQM31 struct {
	X mersenne31.QM31Variable
	Y mersenne31.QM31Variable
}

// CirclePointIndex represents a point on the circle by its index.
// The index i corresponds to g^i where g is the generator.
type CirclePointIndex struct {
	Index frontend.Variable
}

// CircleChip provides circle group operations in gnark circuits.
type CircleChip struct {
	m31Chip   *mersenne31.M31Chip
	api       frontend.API
	isGroth16 bool
}

// NewCircleChip creates a new CircleChip.
func NewCircleChip(api frontend.API, isGroth16 bool) *CircleChip {
	return &CircleChip{
		m31Chip:   mersenne31.NewM31Chip(api, isGroth16),
		api:       api,
		isGroth16: isGroth16,
	}
}

// API returns the frontend API.
func (c *CircleChip) API() frontend.API {
	return c.api
}

// M31Chip returns the M31 chip.
func (c *CircleChip) M31Chip() *mersenne31.M31Chip {
	return c.m31Chip
}

// Generator returns the circle group generator as a CirclePointM31.
func (c *CircleChip) Generator() CirclePointM31 {
	return CirclePointM31{
		X: mersenne31.NewM31Const("2"),
		Y: mersenne31.NewM31Const("1268011823"),
	}
}

// Zero returns the identity element of the circle group: (1, 0).
func (c *CircleChip) Zero() CirclePointM31 {
	return CirclePointM31{
		X: mersenne31.One(),
		Y: mersenne31.Zero(),
	}
}

// AddM31 computes the sum of two points on the M31 circle.
// Circle group law: (x1, y1) + (x2, y2) = (x1*x2 - y1*y2, x1*y2 + y1*x2)
// This is equivalent to complex multiplication: (x1 + iy1)(x2 + iy2).
func (c *CircleChip) AddM31(p1, p2 CirclePointM31) CirclePointM31 {
	// x = x1*x2 - y1*y2
	x1x2 := c.m31Chip.MulM31(p1.X, p2.X)
	y1y2 := c.m31Chip.MulM31(p1.Y, p2.Y)
	x := c.m31Chip.SubM31(x1x2, y1y2)

	// y = x1*y2 + y1*x2
	x1y2 := c.m31Chip.MulM31(p1.X, p2.Y)
	y1x2 := c.m31Chip.MulM31(p1.Y, p2.X)
	y := c.m31Chip.AddM31(x1y2, y1x2)

	return CirclePointM31{X: x, Y: y}
}

// DoubleM31 computes 2*p on the M31 circle.
// 2*(x, y) = (2x^2 - 1, 2xy)
func (c *CircleChip) DoubleM31(p CirclePointM31) CirclePointM31 {
	// x' = 2x^2 - 1
	xSq := c.m31Chip.MulM31(p.X, p.X)
	twoXSq := c.m31Chip.MulM31Const(xSq, 2)
	xNew := c.m31Chip.SubM31(twoXSq, mersenne31.One())

	// y' = 2xy
	xy := c.m31Chip.MulM31(p.X, p.Y)
	yNew := c.m31Chip.MulM31Const(xy, 2)

	return CirclePointM31{X: xNew, Y: yNew}
}

// DoubleX computes the x-coordinate of 2*p given only x.
// double_x(x) = 2x^2 - 1
// This is useful for FRI folding where we only need the x-coordinate.
func (c *CircleChip) DoubleX(x mersenne31.M31Variable) mersenne31.M31Variable {
	xSq := c.m31Chip.MulM31(x, x)
	twoXSq := c.m31Chip.MulM31Const(xSq, 2)
	return c.m31Chip.SubM31(twoXSq, mersenne31.One())
}

// NegM31 computes the negation of a point on the M31 circle.
// -(x, y) = (x, -y)
func (c *CircleChip) NegM31(p CirclePointM31) CirclePointM31 {
	return CirclePointM31{
		X: p.X,
		Y: c.m31Chip.NegM31(p.Y),
	}
}

// SubM31 computes p1 - p2 on the M31 circle.
func (c *CircleChip) SubM31(p1, p2 CirclePointM31) CirclePointM31 {
	negP2 := c.NegM31(p2)
	return c.AddM31(p1, negP2)
}

// ConjugateM31 computes the conjugate of a point: (x, y) -> (x, -y).
// This is the same as negation for the circle group.
func (c *CircleChip) ConjugateM31(p CirclePointM31) CirclePointM31 {
	return c.NegM31(p)
}

// Antipode computes the antipodal point: (x, y) -> (-x, -y).
func (c *CircleChip) Antipode(p CirclePointM31) CirclePointM31 {
	return CirclePointM31{
		X: c.m31Chip.NegM31(p.X),
		Y: c.m31Chip.NegM31(p.Y),
	}
}

// ScalarMul computes scalar * p using double-and-add.
// scalar is a frontend.Variable representing the scalar.
// nBits is the number of bits in the scalar.
func (c *CircleChip) ScalarMul(p CirclePointM31, scalar frontend.Variable, nBits int) CirclePointM31 {
	bits := c.api.ToBinary(scalar, nBits)

	// Start with the identity
	result := c.Zero()

	// Double-and-add from MSB to LSB
	for i := nBits - 1; i >= 0; i-- {
		result = c.DoubleM31(result)

		// Conditionally add p if bit is 1
		sumWithP := c.AddM31(result, p)
		result = c.SelectM31(bits[i], sumWithP, result)
	}

	return result
}

// SelectM31 returns a if cond is true, else b.
func (c *CircleChip) SelectM31(cond frontend.Variable, a, b CirclePointM31) CirclePointM31 {
	return CirclePointM31{
		X: c.m31Chip.SelectM31(cond, a.X, b.X),
		Y: c.m31Chip.SelectM31(cond, a.Y, b.Y),
	}
}

// IndexToPoint converts a CirclePointIndex to a CirclePointM31.
// Uses a hint to compute the actual point, then verifies.
func (c *CircleChip) IndexToPoint(idx CirclePointIndex) CirclePointM31 {
	// Use hint to compute g^idx
	result, err := c.api.Compiler().NewHint(IndexToPointHint, 2, idx.Index)
	if err != nil {
		panic(err)
	}

	p := CirclePointM31{
		X: mersenne31.M31Variable{Value: result[0], UpperBound: new(big.Int).Set(mersenne31.M31Modulus)},
		Y: mersenne31.M31Variable{Value: result[1], UpperBound: new(big.Int).Set(mersenne31.M31Modulus)},
	}

	// Range check the coordinates
	c.m31Chip.ReduceSlow(p.X)
	c.m31Chip.ReduceSlow(p.Y)

	// Verify the point is on the circle: x^2 + y^2 = 1
	c.AssertOnCircle(p)

	return p
}

// AssertOnCircle asserts that a point is on the circle x^2 + y^2 = 1.
func (c *CircleChip) AssertOnCircle(p CirclePointM31) {
	xSq := c.m31Chip.MulM31(p.X, p.X)
	ySq := c.m31Chip.MulM31(p.Y, p.Y)
	sum := c.m31Chip.AddM31(xSq, ySq)
	c.m31Chip.AssertEqM31(sum, mersenne31.One())
}

// QM31 operations (for OOD points)

// ZeroQM31 returns the identity element over QM31.
func (c *CircleChip) ZeroQM31() CirclePointQM31 {
	return CirclePointQM31{
		X: mersenne31.OneQM31(),
		Y: mersenne31.ZeroQM31(),
	}
}

// AddQM31 computes the sum of two points on the QM31 circle.
func (c *CircleChip) AddQM31(p1, p2 CirclePointQM31) CirclePointQM31 {
	// x = x1*x2 - y1*y2
	x1x2 := c.m31Chip.MulQM31(p1.X, p2.X)
	y1y2 := c.m31Chip.MulQM31(p1.Y, p2.Y)
	x := c.m31Chip.SubQM31(x1x2, y1y2)

	// y = x1*y2 + y1*x2
	x1y2 := c.m31Chip.MulQM31(p1.X, p2.Y)
	y1x2 := c.m31Chip.MulQM31(p1.Y, p2.X)
	y := c.m31Chip.AddQM31(x1y2, y1x2)

	return CirclePointQM31{X: x, Y: y}
}

// DoubleQM31 computes 2*p on the QM31 circle.
func (c *CircleChip) DoubleQM31(p CirclePointQM31) CirclePointQM31 {
	// x' = 2x^2 - 1
	xSq := c.m31Chip.MulQM31(p.X, p.X)
	two := mersenne31.NewM31Const("2")
	twoXSq := c.m31Chip.MulQM31ByM31(xSq, two)
	xNew := c.m31Chip.SubQM31ByM31(twoXSq, mersenne31.One())

	// y' = 2xy
	xy := c.m31Chip.MulQM31(p.X, p.Y)
	yNew := c.m31Chip.MulQM31ByM31(xy, two)

	return CirclePointQM31{X: xNew, Y: yNew}
}

// DoubleXQM31 computes the x-coordinate of 2*p given only x (QM31 version).
func (c *CircleChip) DoubleXQM31(x mersenne31.QM31Variable) mersenne31.QM31Variable {
	xSq := c.m31Chip.MulQM31(x, x)
	two := mersenne31.NewM31Const("2")
	twoXSq := c.m31Chip.MulQM31ByM31(xSq, two)
	return c.m31Chip.SubQM31ByM31(twoXSq, mersenne31.One())
}

// NegQM31 computes the negation of a QM31 circle point.
func (c *CircleChip) NegQM31(p CirclePointQM31) CirclePointQM31 {
	return CirclePointQM31{
		X: p.X,
		Y: c.m31Chip.NegQM31(p.Y),
	}
}

// GetRandomPoint draws a random point on the QM31 circle from the channel.
// The point is drawn as random x, then y is computed as sqrt(1 - x^2).
// This function takes the random value as input (drawn from channel externally).
func (c *CircleChip) GetRandomPointFromX(x mersenne31.QM31Variable) CirclePointQM31 {
	// Compute y^2 = 1 - x^2
	xSq := c.m31Chip.MulQM31(x, x)
	ySq := c.m31Chip.SubQM31(mersenne31.OneQM31(), xSq)

	// y = sqrt(y^2) - computed via hint and verified
	// For now, return a placeholder - actual sqrt implementation needed
	return CirclePointQM31{
		X: x,
		Y: ySq, // This should be sqrt(ySq)
	}
}

// SelectQM31 returns a if cond is true, else b.
func (c *CircleChip) SelectQM31(cond frontend.Variable, a, b CirclePointQM31) CirclePointQM31 {
	return CirclePointQM31{
		X: c.m31Chip.SelectQM31(cond, a.X, b.X),
		Y: c.m31Chip.SelectQM31(cond, a.Y, b.Y),
	}
}

// IndexToPointHint computes g^index where g is the circle generator.
func IndexToPointHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("IndexToPointHint expects 1 input")
	}

	index := inputs[0].Uint64()
	p := mersenne31.M31Modulus

	// Generator coordinates
	gx := big.NewInt(int64(M31CircleGenX))
	gy := big.NewInt(int64(M31CircleGenY))

	// Compute g^index using repeated squaring
	rx := big.NewInt(1) // Result x (identity)
	ry := big.NewInt(0) // Result y (identity)

	for index > 0 {
		if index&1 == 1 {
			// result = result * g
			// (rx, ry) = (rx*gx - ry*gy, rx*gy + ry*gx)
			newRx := new(big.Int).Sub(
				new(big.Int).Mul(rx, gx),
				new(big.Int).Mul(ry, gy),
			)
			newRy := new(big.Int).Add(
				new(big.Int).Mul(rx, gy),
				new(big.Int).Mul(ry, gx),
			)
			rx = newRx.Mod(newRx, p)
			ry = newRy.Mod(newRy, p)
		}

		// g = g * g
		newGx := new(big.Int).Sub(
			new(big.Int).Mul(gx, gx),
			new(big.Int).Mul(gy, gy),
		)
		newGy := new(big.Int).Mul(
			new(big.Int).Mul(gx, gy),
			big.NewInt(2),
		)
		gx = newGx.Mod(newGx, p)
		gy = newGy.Mod(newGy, p)

		index >>= 1
	}

	results[0] = rx
	results[1] = ry
	return nil
}

// SubQM31ByM31Point subtracts an M31 circle point from a QM31 circle point.
// Circle subtraction: p1 - p2 = p1 + (-p2) = p1 + (p2.x, -p2.y)
// Using circle group law: (x1, y1) + (x2, y2) = (x1*x2 - y1*y2, x1*y2 + y1*x2)
// So: (x1, y1) - (x2, y2) = (x1, y1) + (x2, -y2) = (x1*x2 + y1*y2, -x1*y2 + y1*x2)
func (c *CircleChip) SubQM31ByM31Point(p1 CirclePointQM31, p2 CirclePointM31) CirclePointQM31 {
	// Lift p2 coordinates to QM31
	p2X := c.m31Chip.M31ToQM31(p2.X)
	p2Y := c.m31Chip.M31ToQM31(p2.Y)

	// x = x1*x2 + y1*y2 (note: + because we're subtracting, i.e., adding conjugate)
	x1x2 := c.m31Chip.MulQM31(p1.X, p2X)
	y1y2 := c.m31Chip.MulQM31(p1.Y, p2Y)
	x := c.m31Chip.AddQM31(x1x2, y1y2)

	// y = y1*x2 - x1*y2
	y1x2 := c.m31Chip.MulQM31(p1.Y, p2X)
	x1y2 := c.m31Chip.MulQM31(p1.X, p2Y)
	y := c.m31Chip.SubQM31(y1x2, x1y2)

	return CirclePointQM31{X: x, Y: y}
}

// SubgroupGeneratorM31 returns the generator of the subgroup of size 2^log_size.
// G_n = g^(2^(31-log_size)) where g is the full group generator.
// This is used for computing the trace generator step for shifted points.
func (c *CircleChip) SubgroupGeneratorM31(logSize uint32) CirclePointM31 {
	// index = 2^(31 - logSize)
	index := uint64(1) << (M31CircleLogOrder - logSize)
	idx := CirclePointIndex{Index: frontend.Variable(index)}
	return c.IndexToPoint(idx)
}
