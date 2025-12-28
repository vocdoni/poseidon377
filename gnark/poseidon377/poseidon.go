package poseidon377

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"

	"github.com/vocdoni/poseidon377/internal/params"
)

// circuitPermutation mirrors the native permutation but emits gnark constraints.
type circuitPermutation struct {
	params *params.Parameters
}

// newCircuitPermutation builds a circuit gadget for the provided rate.
func newCircuitPermutation(rate int) (*circuitPermutation, error) {
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
	return &circuitPermutation{params: p}, nil
}

// Hash computes H(domain, inputs...) inside a gnark circuit.
func Hash(api frontend.API, domain frontend.Variable, inputs ...frontend.Variable) (frontend.Variable, error) {
	rate := len(inputs)
	if rate < 1 {
		var zero frontend.Variable
		return zero, fmt.Errorf("poseidon377: need at least 1 limb")
	}
	gadget, err := newCircuitPermutation(rate)
	if err != nil {
		var zero frontend.Variable
		return zero, err
	}
	return gadget.hash(api, domain, inputs)
}

func (p *circuitPermutation) hash(api frontend.API, domain frontend.Variable, inputs []frontend.Variable) (frontend.Variable, error) {
	if len(inputs)+1 != p.params.StateSize {
		var zero frontend.Variable
		return zero, fmt.Errorf("poseidon377: expected %d limbs, got %d", p.params.StateSize, len(inputs)+1)
	}
	state := make([]frontend.Variable, p.params.StateSize)
	state[0] = domain
	copy(state[1:], inputs)
	state = p.permute(api, state)
	return state[1], nil
}

func (p *circuitPermutation) permute(api frontend.API, state []frontend.Variable) []frontend.Variable {
	t := p.params.StateSize
	rF := p.params.FullRounds / 2
	arc := p.params.OptimizedArc

	for r := 0; r < rF; r++ {
		circuitAddArcRow(api, state, arc, r, t)
		circuitFullSBox(api, state, p.params.Alpha)
		state = circuitMix(api, state, p.params.MDS, t)
	}
	round := rF

	circuitAddArcRow(api, state, arc, round, t)
	state = circuitMix(api, state, p.params.OptimizedMDS.MI, t)

	for r := 0; r < p.params.PartialRounds-1; r++ {
		state[0] = circuitExp17(api, state[0])
		round++
		state[0] = api.Add(state[0], arc[round*t])
		state = circuitSparse(api, state, p.params, p.params.PartialRounds-r-1)
	}

	state[0] = circuitExp17(api, state[0])
	state = circuitSparse(api, state, p.params, 0)
	round++

	for r := 0; r < rF; r++ {
		circuitAddArcRow(api, state, arc, round, t)
		circuitFullSBox(api, state, p.params.Alpha)
		state = circuitMix(api, state, p.params.MDS, t)
		round++
	}

	return state
}

func circuitAddArcRow(api frontend.API, state []frontend.Variable, arc []fr.Element, row, width int) {
	offset := row * width
	for i := 0; i < width; i++ {
		state[i] = api.Add(state[i], arc[offset+i])
	}
}

func circuitMix(api frontend.API, state []frontend.Variable, matrix []fr.Element, width int) []frontend.Variable {
	out := make([]frontend.Variable, width)
	for i := 0; i < width; i++ {
		offset := i * width
		sum := api.Mul(state[0], matrix[offset])
		for j := 1; j < width; j++ {
			sum = api.Add(sum, api.Mul(state[j], matrix[offset+j]))
		}
		out[i] = sum
	}
	return out
}

func circuitSparse(api frontend.API, state []frontend.Variable, p *params.Parameters, round int) []frontend.Variable {
	t := p.StateSize
	subSize := t - 1
	v := p.OptimizedMDS.VCollection[round*subSize : (round+1)*subSize]
	wHat := p.OptimizedMDS.WHatCollection[round*subSize : (round+1)*subSize]

	out := make([]frontend.Variable, t)
	newZero := api.Mul(state[0], p.OptimizedMDS.M00)
	for i := 0; i < subSize; i++ {
		term := api.Add(api.Mul(state[0], v[i]), state[i+1])
		out[i+1] = term
		newZero = api.Add(newZero, api.Mul(state[i+1], wHat[i]))
	}
	out[0] = newZero
	return out
}

func circuitFullSBox(api frontend.API, state []frontend.Variable, alpha params.Alpha) {
	if alpha.Inverse {
		panic("poseidon377: inverse alpha not supported")
	}
	for i := range state {
		state[i] = circuitExp17(api, state[i])
	}
}

func circuitExp17(api frontend.API, v frontend.Variable) frontend.Variable {
	v2 := api.Mul(v, v)
	v4 := api.Mul(v2, v2)
	v8 := api.Mul(v4, v4)
	v16 := api.Mul(v8, v8)
	return api.Mul(v16, v)
}
