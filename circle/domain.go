// Package circle implements circle domain operations for Circle STARKs.
package circle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// Coset represents a coset of the circle group.
// A coset is defined by an initial point and a step size.
// The coset is: {initial, initial + step, initial + 2*step, ...}
type Coset struct {
	// InitialIndex is the index of the first point in the coset
	InitialIndex CirclePointIndex
	// StepIndex is the step between consecutive points
	StepIndex CirclePointIndex
	// LogSize is the log2 of the coset size
	LogSize frontend.Variable
}

// CircleDomain represents a domain for circle polynomial evaluation.
// The domain is a coset of size 2^log_size.
type CircleDomain struct {
	HalfCoset Coset
}

// LineDomain represents a domain on the line (used after circle-to-line folding in FRI).
type LineDomain struct {
	Coset Coset
}

// CanonicCoset represents the standard coset used in stwo.
// This is G_{2n} + <G_n> where G_n is the order-n subgroup generator.
type CanonicCoset struct {
	Coset Coset
}

// NewCoset creates a new coset with the given parameters.
func NewCoset(initialIndex, stepIndex CirclePointIndex, logSize frontend.Variable) Coset {
	return Coset{
		InitialIndex: initialIndex,
		StepIndex:    stepIndex,
		LogSize:      logSize,
	}
}

// NewCanonicCoset creates a canonic coset of size 2^logSize.
// The canonic coset is G_{2n} + <G_n> where n = 2^logSize.
func NewCanonicCoset(api frontend.API, logSize frontend.Variable) CanonicCoset {
	// Initial index: 2^(31 - logSize - 1)
	// Step index: 2^(31 - logSize)

	// For a fixed logSize, we compute:
	// initial = 2^(30 - logSize) = 2^30 / 2^logSize
	// step = 2^(31 - logSize) = 2^31 / 2^logSize

	return CanonicCoset{
		Coset: Coset{
			InitialIndex: CirclePointIndex{Index: frontend.Variable(0)}, // Placeholder
			StepIndex:    CirclePointIndex{Index: frontend.Variable(0)}, // Placeholder
			LogSize:      logSize,
		},
	}
}

// NewCircleDomain creates a circle domain from a half coset.
func NewCircleDomain(halfCoset Coset) CircleDomain {
	return CircleDomain{HalfCoset: halfCoset}
}

// Size returns 2^logSize.
func (c *Coset) Size(api frontend.API) frontend.Variable {
	// This would need to compute 2^logSize which is complex in circuits
	// For now, return a placeholder
	return api.Mul(c.LogSize, 1) // Placeholder
}

// At returns the point at the given index in the coset.
func (c *Coset) At(circleChip *CircleChip, index frontend.Variable) CirclePointM31 {
	// point = initial + index * step
	// index in the coset corresponds to: initial_index + index * step_index

	// Compute the actual circle point index
	stepTimesIndex := circleChip.api.Mul(c.StepIndex.Index, index)
	pointIndex := circleChip.api.Add(c.InitialIndex.Index, stepTimesIndex)

	// Convert index to point
	return circleChip.IndexToPoint(CirclePointIndex{Index: pointIndex})
}

// IndexAt returns the circle point index at the given coset index.
func (c *Coset) IndexAt(api frontend.API, index frontend.Variable) CirclePointIndex {
	stepTimesIndex := api.Mul(c.StepIndex.Index, index)
	pointIndex := api.Add(c.InitialIndex.Index, stepTimesIndex)
	return CirclePointIndex{Index: pointIndex}
}

// GetRandomPoint draws a random point from the channel for OOD evaluation.
// This creates a CirclePointQM31 from random QM31 values.
func (c *CircleChip) GetRandomCirclePoint(
	t mersenne31.QM31Variable,
) CirclePointQM31 {
	// The method used in stwo:
	// Given random t, compute point (x, y) where:
	// x = (1 - t^2) / (1 + t^2)
	// y = 2t / (1 + t^2)
	// This parametrizes the circle via the stereographic projection.

	// Compute t^2
	tSq := c.m31Chip.MulQM31(t, t)

	// Compute 1 + t^2
	one := mersenne31.OneQM31()
	onePlusTSq := c.m31Chip.AddQM31(one, tSq)

	// Compute 1 - t^2
	oneMinusTSq := c.m31Chip.SubQM31(one, tSq)

	// Compute 2t
	two := mersenne31.NewM31Const("2")
	twoT := c.m31Chip.MulQM31ByM31(t, two)

	// Compute inverses
	onePlusTSqInv := c.m31Chip.InvQM31(onePlusTSq)

	// x = (1 - t^2) / (1 + t^2)
	x := c.m31Chip.MulQM31(oneMinusTSq, onePlusTSqInv)

	// y = 2t / (1 + t^2)
	y := c.m31Chip.MulQM31(twoT, onePlusTSqInv)

	return CirclePointQM31{X: x, Y: y}
}

// TwiddleAt returns the twiddle factor for FRI folding at a given index.
// The twiddle factor is the y-coordinate of the point at that index.
func (c *Coset) TwiddleAt(circleChip *CircleChip, index frontend.Variable) mersenne31.M31Variable {
	point := c.At(circleChip, index)
	return point.Y
}

// Domain returns the CircleDomain for this coset.
func (c *CanonicCoset) Domain() CircleDomain {
	return CircleDomain{
		HalfCoset: c.Coset,
	}
}

// CircleDomain methods

// At returns the point at the given index in the domain.
func (d *CircleDomain) At(circleChip *CircleChip, index frontend.Variable) CirclePointM31 {
	return d.HalfCoset.At(circleChip, index)
}

// LogSize returns the log2 of the domain size.
func (d *CircleDomain) LogSize() frontend.Variable {
	return d.HalfCoset.LogSize
}

// LineDomain methods

// At returns the x-coordinate of the point at the given index.
func (d *LineDomain) At(circleChip *CircleChip, index frontend.Variable) mersenne31.M31Variable {
	point := d.Coset.At(circleChip, index)
	return point.X
}

// DoubleAt returns 2x for the x-coordinate at the given index.
func (d *LineDomain) DoubleAt(circleChip *CircleChip, index frontend.Variable) mersenne31.M31Variable {
	x := d.At(circleChip, index)
	return circleChip.DoubleX(x)
}

// LogSize returns the log2 of the domain size.
func (d *LineDomain) LogSize() frontend.Variable {
	return d.Coset.LogSize
}

// NewLineDomainFromCircle creates a LineDomain from a CircleDomain after circle-to-line folding.
func NewLineDomainFromCircle(api frontend.API, circleDomain CircleDomain) LineDomain {
	// After folding, the size is halved
	newLogSize := api.Sub(circleDomain.HalfCoset.LogSize, 1)

	return LineDomain{
		Coset: Coset{
			InitialIndex: circleDomain.HalfCoset.InitialIndex,
			StepIndex:    circleDomain.HalfCoset.StepIndex,
			LogSize:      newLogSize,
		},
	}
}
