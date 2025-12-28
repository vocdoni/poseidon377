package poseidon377

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/vocdoni/poseidon377/internal/params"
)

const (
	maxRate            = 7
	MaxMultiHashInputs = 256
)

// Hash computes the Poseidon hash over emulated BLS12-377 field elements.
func Hash(api frontend.API, domain emulated.Element[FrParams], inputs ...emulated.Element[FrParams]) (emulated.Element[FrParams], error) {
	rate := len(inputs)
	if rate < 1 {
		var zero emulated.Element[FrParams]
		return zero, fmt.Errorf("poseidon377: need at least 1 limb")
	}
	p, err := nativeParams(rate)
	if err != nil {
		var zero emulated.Element[FrParams]
		return zero, err
	}
	if err := params.Validate(p); err != nil {
		var zero emulated.Element[FrParams]
		return zero, err
	}

	field, err := emulated.NewField[FrParams](api)
	if err != nil {
		var zero emulated.Element[FrParams]
		return zero, err
	}

	state := make([]emulated.Element[FrParams], p.StateSize)
	state[0] = domain
	copy(state[1:], inputs)

	permute(field, p, state)
	// Ensure canonical output.
	out := field.Reduce(&state[1])
	return *out, nil
}

// MultiHash hashes an arbitrary number of emulated elements (up to MaxMultiHashInputs) by chunking with the highest available rate (7).
func MultiHash(api frontend.API, domain emulated.Element[FrParams], inputs ...emulated.Element[FrParams]) (emulated.Element[FrParams], error) {
	var zero emulated.Element[FrParams]
	if len(inputs) == 0 {
		return zero, fmt.Errorf("poseidon377: need at least 1 limb")
	}
	if len(inputs) > MaxMultiHashInputs {
		return zero, fmt.Errorf("poseidon377: too many inputs (%d > %d)", len(inputs), MaxMultiHashInputs)
	}

	current := make([]emulated.Element[FrParams], len(inputs))
	copy(current, inputs)

	for len(current) > maxRate {
		next := make([]emulated.Element[FrParams], 0, (len(current)+maxRate-1)/maxRate)
		for i := 0; i < len(current); i += maxRate {
			end := min(i+maxRate, len(current))
			h, err := Hash(api, domain, current[i:end]...)
			if err != nil {
				return zero, err
			}
			next = append(next, h)
		}
		current = next
	}

	return Hash(api, domain, current...)
}

// permute mutates the state in place using the optimized Penumbra schedule.
func permute(field *emulated.Field[FrParams], p *params.Parameters, state []emulated.Element[FrParams]) {
	ptrState := make([]*emulated.Element[FrParams], len(state))
	for i := range state {
		ptrState[i] = field.NewElement(state[i])
	}

	t := p.StateSize
	rF := p.FullRounds / 2
	arc := p.OptimizedArc

	// First half of full rounds.
	for r := range rF {
		addArcRow(field, ptrState, arc, r, t)
		fullSBox(field, ptrState, p.Alpha)
		ptrState = mixLayerMDS(field, p, ptrState)
	}
	round := rF

	// First partial round constants + dense mix (M_i).
	addArcRow(field, ptrState, arc, round, t)
	ptrState = mixLayerMI(field, p, ptrState)

	// Middle partial rounds.
	for r := 0; r < p.PartialRounds-1; r++ {
		partialSBox(field, ptrState, p.Alpha)
		round++
		arc0 := constElement(field, arc[round*t])
		ptrState[0] = field.Add(ptrState[0], &arc0)
		ptrState = sparseMatMul(field, p, ptrState, p.PartialRounds-r-1)
	}

	// Final partial round.
	partialSBox(field, ptrState, p.Alpha)
	ptrState = sparseMatMul(field, p, ptrState, 0)
	round++

	// Second half of full rounds.
	for range rF {
		addArcRow(field, ptrState, arc, round, t)
		fullSBox(field, ptrState, p.Alpha)
		ptrState = mixLayerMDS(field, p, ptrState)
		round++
	}

	for i := range state {
		state[i] = *ptrState[i]
	}
}

func addArcRow(field *emulated.Field[FrParams], state []*emulated.Element[FrParams], arc []fr.Element, row, width int) {
	offset := row * width
	for i := range width {
		c := constElement(field, arc[offset+i])
		state[i] = field.Add(state[i], &c)
	}
}

func mixLayerMDS(field *emulated.Field[FrParams], p *params.Parameters, state []*emulated.Element[FrParams]) []*emulated.Element[FrParams] {
	t := p.StateSize
	newState := make([]*emulated.Element[FrParams], t)
	for i := range t {
		sum := field.NewElement(emulated.ValueOf[FrParams](0))
		rowOffset := i * t
		for j := range t {
			c := constElement(field, p.MDS[rowOffset+j])
			prod := field.Mul(&c, state[j])
			sum = field.Add(sum, prod)
		}
		newState[i] = sum
	}
	return newState
}

func mixLayerMI(field *emulated.Field[FrParams], p *params.Parameters, state []*emulated.Element[FrParams]) []*emulated.Element[FrParams] {
	t := p.StateSize
	newState := make([]*emulated.Element[FrParams], t)
	for i := range t {
		sum := field.NewElement(emulated.ValueOf[FrParams](0))
		rowOffset := i * t
		for j := range t {
			c := constElement(field, p.OptimizedMDS.MI[rowOffset+j])
			prod := field.Mul(&c, state[j])
			sum = field.Add(sum, prod)
		}
		newState[i] = sum
	}
	return newState
}

func sparseMatMul(field *emulated.Field[FrParams], p *params.Parameters, state []*emulated.Element[FrParams], round int) []*emulated.Element[FrParams] {
	t := p.StateSize
	subSize := t - 1
	v := p.OptimizedMDS.VCollection[round*subSize : (round+1)*subSize]
	wHat := p.OptimizedMDS.WHatCollection[round*subSize : (round+1)*subSize]

	newZero := field.NewElement(emulated.ValueOf[FrParams](0))
	newState := make([]*emulated.Element[FrParams], t)

	for i := range subSize {
		coeff := constElement(field, v[i])
		term := field.Mul(&coeff, state[0])
		term = field.Add(term, state[i+1])
		newState[i+1] = term

		wc := constElement(field, wHat[i])
		contrib := field.Mul(&wc, state[i+1])
		newZero = field.Add(newZero, contrib)
	}

	m00 := constElement(field, p.OptimizedMDS.M00)
	mul := field.Mul(&m00, state[0])
	newZero = field.Add(newZero, mul)

	newState[0] = newZero
	return newState
}

func partialSBox(field *emulated.Field[FrParams], state []*emulated.Element[FrParams], alpha params.Alpha) {
	switch {
	case alpha.Inverse:
		panic("poseidon377: inverse alpha not supported")
	default:
		state[0] = exp17(field, state[0])
	}
}

func fullSBox(field *emulated.Field[FrParams], state []*emulated.Element[FrParams], alpha params.Alpha) {
	for i := range state {
		switch {
		case alpha.Inverse:
			panic("poseidon377: inverse alpha not supported")
		default:
			state[i] = exp17(field, state[i])
		}
	}
}

func exp17(field *emulated.Field[FrParams], x *emulated.Element[FrParams]) *emulated.Element[FrParams] {
	x2 := field.Mul(x, x)
	x4 := field.Mul(x2, x2)
	x8 := field.Mul(x4, x4)
	x16 := field.Mul(x8, x8)
	return field.Mul(x16, x)
}
