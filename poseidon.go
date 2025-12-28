package poseidon377

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"

	"github.com/vocdoni/poseidon377/internal/params"
)

const (
	maxRate            = 7
	MaxMultiHashInputs = 256
)

// permutation implements the Poseidon permutation over bls12-377 (Penumbra parameters).
type permutation struct {
	params *params.Parameters
}

// newPermutation instantiates a permutation for the given rate (number of message limbs).
// The state width is rate+1 (first limb is the domain separator/capacity).
func newPermutation(rate int) (*permutation, error) {
	p, ok := params.AllParameters[rate]
	if !ok {
		return nil, fmt.Errorf("poseidon377: unsupported rate %d", rate)
	}
	if p.StateSize != rate+1 {
		return nil, fmt.Errorf("poseidon377: inconsistent parameter set for rate %d (state size %d)", rate, p.StateSize)
	}
	if err := params.Validate(p); err != nil {
		return nil, err
	}
	return &permutation{params: p}, nil
}

// Hash applies the Poseidon2 permutation to [domain, inputs...] and returns the sponge output (state[1]).
func Hash(domain fr.Element, inputs ...fr.Element) (fr.Element, error) {
	rate := len(inputs)
	if rate < 1 {
		return fr.Element{}, fmt.Errorf("poseidon377: need at least 1 limb")
	}
	perm, err := newPermutation(rate)
	if err != nil {
		return fr.Element{}, err
	}

	state := make([]fr.Element, perm.params.StateSize)
	state[0] = domain
	copy(state[1:], inputs)

	perm.permute(state)
	return state[1], nil
}

// DomainFromLEBytes mirrors decaf377::Fq::from_le_bytes_mod_order.
func DomainFromLEBytes(data []byte) fr.Element {
	reversed := make([]byte, len(data))
	for i := range data {
		reversed[len(data)-1-i] = data[i]
	}
	bi := new(big.Int).SetBytes(reversed)
	var out fr.Element
	out.SetBigInt(bi)
	return out
}

// MultiHash hashes an arbitrary-length list of field elements by chunking with the highest available rate (7).
// Domain is placed in the capacity slot on every chunk. Supports up to MaxMultiHashInputs inputs.
func MultiHash(domain fr.Element, inputs ...fr.Element) (fr.Element, error) {
	if len(inputs) == 0 {
		return fr.Element{}, fmt.Errorf("poseidon377: need at least 1 limb")
	}
	if len(inputs) > MaxMultiHashInputs {
		return fr.Element{}, fmt.Errorf("poseidon377: too many inputs (%d > %d)", len(inputs), MaxMultiHashInputs)
	}

	current := make([]fr.Element, len(inputs))
	copy(current, inputs)

	for len(current) > maxRate {
		next := make([]fr.Element, 0, (len(current)+maxRate-1)/maxRate)
		for i := 0; i < len(current); i += maxRate {
			end := i + maxRate
			if end > len(current) {
				end = len(current)
			}
			h, err := hashChunk(domain, current[i:end])
			if err != nil {
				return fr.Element{}, err
			}
			next = append(next, h)
		}
		current = next
	}

	return hashChunk(domain, current)
}

func hashChunk(domain fr.Element, chunk []fr.Element) (fr.Element, error) {
	perm, err := newPermutation(len(chunk))
	if err != nil {
		return fr.Element{}, err
	}
	state := make([]fr.Element, perm.params.StateSize)
	state[0] = domain
	copy(state[1:], chunk)
	perm.permute(state)
	return state[1], nil
}

// permute mutates the state in place using the optimized Penumbra schedule.
func (p *permutation) permute(state []fr.Element) {
	t := p.params.StateSize
	rF := p.params.FullRounds / 2
	arc := p.params.OptimizedArc

	// First half of full rounds.
	for r := 0; r < rF; r++ {
		addArcRow(state, arc, r, t)
		fullSBox(state, p.params.Alpha)
		p.mixLayerMDS(state)
	}
	round := rF

	// First partial round constants + dense mix (M_i).
	addArcRow(state, arc, round, t)
	p.mixLayerMI(state)

	// Middle partial rounds.
	for r := 0; r < p.params.PartialRounds-1; r++ {
		partialSBox(state, p.params.Alpha)
		round++
		state[0].Add(&state[0], &arc[round*t])
		p.sparseMatMul(state, p.params.PartialRounds-r-1)
	}

	// Final partial round.
	partialSBox(state, p.params.Alpha)
	p.sparseMatMul(state, 0)
	round++

	// Second half of full rounds.
	for r := 0; r < rF; r++ {
		addArcRow(state, arc, round, t)
		fullSBox(state, p.params.Alpha)
		p.mixLayerMDS(state)
		round++
	}
}

func (p *permutation) mixLayerMDS(state []fr.Element) {
	t := p.params.StateSize
	newState := make([]fr.Element, t)
	for i := 0; i < t; i++ {
		var sum fr.Element
		rowOffset := i * t
		for j := 0; j < t; j++ {
			var prod fr.Element
			coeff := p.params.MDS[rowOffset+j]
			prod.Mul(&coeff, &state[j])
			sum.Add(&sum, &prod)
		}
		newState[i] = sum
	}
	copy(state, newState)
}

func (p *permutation) mixLayerMI(state []fr.Element) {
	t := p.params.StateSize
	newState := make([]fr.Element, t)
	for i := 0; i < t; i++ {
		var sum fr.Element
		rowOffset := i * t
		for j := 0; j < t; j++ {
			var prod fr.Element
			coeff := p.params.OptimizedMDS.MI[rowOffset+j]
			prod.Mul(&coeff, &state[j])
			sum.Add(&sum, &prod)
		}
		newState[i] = sum
	}
	copy(state, newState)
}

func (p *permutation) sparseMatMul(state []fr.Element, round int) {
	t := p.params.StateSize
	subSize := t - 1
	v := p.params.OptimizedMDS.VCollection[round*subSize : (round+1)*subSize]
	wHat := p.params.OptimizedMDS.WHatCollection[round*subSize : (round+1)*subSize]

	var newZero fr.Element
	newState := make([]fr.Element, t)

	for i := 0; i < subSize; i++ {
		var term fr.Element
		term.Mul(&v[i], &state[0])
		term.Add(&term, &state[i+1])
		newState[i+1] = term

		var contrib fr.Element
		contrib.Mul(&wHat[i], &state[i+1])
		newZero.Add(&newZero, &contrib)
	}

	var mul fr.Element
	mul.Mul(&p.params.OptimizedMDS.M00, &state[0])
	newZero.Add(&newZero, &mul)

	newState[0] = newZero
	copy(state, newState)
}

func addArcRow(state []fr.Element, arc []fr.Element, row, width int) {
	offset := row * width
	for i := 0; i < width; i++ {
		state[i].Add(&state[i], &arc[offset+i])
	}
}

func partialSBox(state []fr.Element, alpha params.Alpha) {
	switch {
	case alpha.Inverse:
		panic("poseidon377: inverse alpha not supported")
	default:
		exp17(&state[0])
	}
}

func fullSBox(state []fr.Element, alpha params.Alpha) {
	for i := range state {
		switch {
		case alpha.Inverse:
			panic("poseidon377: inverse alpha not supported")
		default:
			exp17(&state[i])
		}
	}
}

func exp17(x *fr.Element) {
	var x2, x4, x8, x16 fr.Element
	x2.Mul(x, x)
	x4.Mul(&x2, &x2)
	x8.Mul(&x4, &x4)
	x16.Mul(&x8, &x8)
	x.Mul(&x16, x)
}
