package poseidon377

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"

	emposeidon "github.com/vocdoni/poseidon377/gnark/emulated/poseidon377"
	"github.com/vocdoni/poseidon377/internal/params"
)

type emuSmallCircuit struct {
	Domain   emulated.Element[emposeidon.FrParams]
	Inputs   [2]emulated.Element[emposeidon.FrParams]
	Expected emulated.Element[emposeidon.FrParams] `gnark:",public"`
}

func (c *emuSmallCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[emposeidon.FrParams](api)
	if err != nil {
		return err
	}
	out, err := emposeidon.Hash(api, c.Domain, c.Inputs[0], c.Inputs[1])
	if err != nil {
		return err
	}
	field.AssertIsEqual(&out, &c.Expected)
	return nil
}

type emuSizedCircuit struct {
	Domain   emulated.Element[emposeidon.FrParams]
	Inputs   []emulated.Element[emposeidon.FrParams]
	Expected emulated.Element[emposeidon.FrParams] `gnark:",public"`
}

func (c *emuSizedCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[emposeidon.FrParams](api)
	if err != nil {
		return err
	}
	out, err := emposeidon.MultiHash(api, c.Domain, c.Inputs...)
	if err != nil {
		return err
	}
	field.AssertIsEqual(&out, &c.Expected)
	return nil
}

func TestEmulatedHashMatchesNative(t *testing.T) {
	assert := test.NewAssert(t)
	domain := DomainFromLEBytes([]byte("Penumbra_TestVec"))
	var a, b fr.Element
	a.SetUint64(1)
	b.SetUint64(2)
	native, err := Hash(domain, a, b)
	if err != nil {
		t.Fatal(err)
	}

	ref, err := bigIntHash(domain, a, b)
	if err != nil {
		t.Fatal(err)
	}
	var refEl fr.Element
	refEl.SetBigInt(ref)
	if !native.Equal(&refEl) {
		t.Fatalf("native vs bigint mismatch: %s vs %s", native.String(), refEl.String())
	}

	witness := emuSmallCircuit{
		Domain:   valueOf(domain),
		Inputs:   [2]emulated.Element[emposeidon.FrParams]{valueOf(a), valueOf(b)},
		Expected: valueOf(native),
	}

	assert.ProverSucceeded(
		&emuSmallCircuit{},
		&witness,
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16),
	)
}

func TestEmulatedMultiHashBW6(t *testing.T) {
	assert := test.NewAssert(t)
	domain := DomainFromLEBytes([]byte("Penumbra_TestVec"))

	setInputs := func(n int) []fr.Element {
		out := make([]fr.Element, n)
		for i := range out {
			out[i].SetUint64(uint64(i + 1))
		}
		return out
	}

	t.Run("size-16", func(t *testing.T) { runSizedEmulated(t, assert, domain, setInputs(16)) })
	t.Run("size-32", func(t *testing.T) { runSizedEmulated(t, assert, domain, setInputs(32)) })
	t.Run("size-64", func(t *testing.T) { runSizedEmulated(t, assert, domain, setInputs(64)) })
	t.Run("size-128", func(t *testing.T) { runSizedEmulated(t, assert, domain, setInputs(128)) })
	t.Run("size-256", func(t *testing.T) { runSizedEmulated(t, assert, domain, setInputs(256)) })
}

func runSizedEmulated(t *testing.T, assert *test.Assert, domain fr.Element, inputs []fr.Element) {
	expected, _ := MultiHash(domain, inputs...)
	witness := emuSizedCircuit{
		Domain:   valueOf(domain),
		Inputs:   make([]emulated.Element[emposeidon.FrParams], len(inputs)),
		Expected: valueOf(expected),
	}
	for i, v := range inputs {
		witness.Inputs[i] = valueOf(v)
	}

	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &emuSizedCircuit{
		Inputs: make([]emulated.Element[emposeidon.FrParams], len(inputs)),
	})
	if err != nil {
		t.Fatalf("compile n=%d: %v", len(inputs), err)
	}
	t.Logf("emulated multihash constraints n=%d (bw6-761 host, r1cs): %d", len(inputs), ccs.GetNbConstraints())

	assert.ProverSucceeded(
		&emuSizedCircuit{Inputs: make([]emulated.Element[emposeidon.FrParams], len(inputs))},
		&witness,
		test.WithCurves(ecc.BW6_761),
		test.WithBackends(backend.GROTH16),
	)
}

func valueOf(e fr.Element) emulated.Element[emposeidon.FrParams] {
	return emulated.ValueOf[emposeidon.FrParams](e.BigInt(new(big.Int)))
}

// Reference bigint implementation to sanity-check constants and schedule.
func bigIntHash(domain fr.Element, inputs ...fr.Element) (*big.Int, error) {
	rate := len(inputs)
	p, ok := params.AllParameters[rate]
	if !ok {
		return nil, fmt.Errorf("unsupported rate %d", rate)
	}
	mod := fr.Modulus()
	t := p.StateSize
	state := make([]*big.Int, t)
	state[0] = domain.BigInt(new(big.Int))
	for i := 0; i < rate; i++ {
		state[i+1] = inputs[i].BigInt(new(big.Int))
	}
	arc := elemsToBig(p.OptimizedArc)

	rF := p.FullRounds / 2
	// First full half.
	for r := 0; r < rF; r++ {
		addArcRowBig(state, arc, r, t, mod)
		fullSBoxBig(state, p.Alpha, mod)
		state = mixLayerBig(state, elemsToBig(p.MDS), t, mod)
	}
	round := rF

	// First partial + MI.
	addArcRowBig(state, arc, round, t, mod)
	state = mixLayerBig(state, elemsToBig(p.OptimizedMDS.MI), t, mod)

	// Middle partial.
	for r := 0; r < p.PartialRounds-1; r++ {
		partialSBoxBig(state, p.Alpha, mod)
		round++
		state[0].Add(state[0], arc[round*t]).Mod(state[0], mod)
		state = sparseMatMulBig(state, p, p.PartialRounds-r-1, mod)
	}

	// Final partial.
	partialSBoxBig(state, p.Alpha, mod)
	state = sparseMatMulBig(state, p, 0, mod)
	round++

	// Second half of full rounds.
	for r := 0; r < rF; r++ {
		addArcRowBig(state, arc, round, t, mod)
		fullSBoxBig(state, p.Alpha, mod)
		state = mixLayerBig(state, elemsToBig(p.MDS), t, mod)
		round++
	}

	return new(big.Int).Set(state[1]), nil
}

func elemsToBig(es []fr.Element) []*big.Int {
	out := make([]*big.Int, len(es))
	for i := range es {
		out[i] = es[i].BigInt(new(big.Int))
	}
	return out
}

func addArcRowBig(state []*big.Int, arc []*big.Int, row, width int, mod *big.Int) {
	offset := row * width
	for i := 0; i < width; i++ {
		state[i].Add(state[i], arc[offset+i]).Mod(state[i], mod)
	}
}

func mixLayerBig(state []*big.Int, mds []*big.Int, t int, mod *big.Int) []*big.Int {
	newState := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		sum := big.NewInt(0)
		rowOffset := i * t
		for j := 0; j < t; j++ {
			prod := new(big.Int).Mul(mds[rowOffset+j], state[j])
			sum.Add(sum, prod)
		}
		sum.Mod(sum, mod)
		newState[i] = sum
	}
	return newState
}

func sparseMatMulBig(state []*big.Int, p *params.Parameters, round int, mod *big.Int) []*big.Int {
	t := p.StateSize
	subSize := t - 1
	v := elemsToBig(p.OptimizedMDS.VCollection[round*subSize : (round+1)*subSize])
	wHat := elemsToBig(p.OptimizedMDS.WHatCollection[round*subSize : (round+1)*subSize])

	newState := make([]*big.Int, t)
	newZero := big.NewInt(0)

	for i := 0; i < subSize; i++ {
		term := new(big.Int).Mul(v[i], state[0])
		term.Add(term, state[i+1])
		term.Mod(term, mod)
		newState[i+1] = term

		contrib := new(big.Int).Mul(wHat[i], state[i+1])
		newZero.Add(newZero, contrib)
	}
	mul := new(big.Int).Mul(p.OptimizedMDS.M00.BigInt(new(big.Int)), state[0])
	newZero.Add(newZero, mul)
	newZero.Mod(newZero, mod)
	newState[0] = newZero
	return newState
}

func fullSBoxBig(state []*big.Int, alpha params.Alpha, mod *big.Int) {
	for i := range state {
		partialSBoxElemBig(state[i], alpha, mod)
	}
}

func partialSBoxBig(state []*big.Int, alpha params.Alpha, mod *big.Int) {
	partialSBoxElemBig(state[0], alpha, mod)
}

func partialSBoxElemBig(x *big.Int, alpha params.Alpha, mod *big.Int) {
	if alpha.Inverse {
		panic("inverse alpha not supported")
	}
	// exp17 via square-and-multiply
	x.Exp(x, big.NewInt(17), mod)
}

// Debug circuit to inspect limb outputs from emulated poseidon.
type emuDebugCircuit struct {
	Domain emulated.Element[emposeidon.FrParams]
	Inputs [2]emulated.Element[emposeidon.FrParams]
}

func (c *emuDebugCircuit) Define(api frontend.API) error {
	out, err := emposeidon.Hash(api, c.Domain, c.Inputs[0], c.Inputs[1])
	if err != nil {
		return err
	}
	for i, limb := range out.Limbs {
		api.Println("out limb", i, limb)
	}
	return nil
}

// Minimal sanity check for emulated field ops.
type emuAddCircuit struct {
	A emulated.Element[emposeidon.FrParams]
	B emulated.Element[emposeidon.FrParams]
}

func (c *emuAddCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[emposeidon.FrParams](api)
	if err != nil {
		return err
	}
	sum := f.Add(&c.A, &c.B)
	for i, limb := range sum.Limbs {
		api.Println("add limb", i, limb)
	}
	return nil
}

func TestDebugEmulatedOutput(t *testing.T) {
	t.Skip("debug")
	domain := DomainFromLEBytes([]byte("Penumbra_TestVec"))
	var a, b fr.Element
	a.SetUint64(1)
	b.SetUint64(2)

	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &emuDebugCircuit{})
	if err != nil {
		t.Fatalf("compile debug: %v", err)
	}
	witness := &emuDebugCircuit{
		Domain: valueOf(domain),
		Inputs: [2]emulated.Element[emposeidon.FrParams]{valueOf(a), valueOf(b)},
	}
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	zlog := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.DebugLevel)
	if _, err := ccs.Solve(w, solver.WithLogger(zlog)); err != nil {
		t.Fatalf("solve debug: %v", err)
	}
}

func TestEmulatedAddDebug(t *testing.T) {
	t.Skip("debug")
	var a, b fr.Element
	a.SetUint64(1)
	b.SetUint64(2)
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &emuAddCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	witness := &emuAddCircuit{
		A: valueOf(a),
		B: valueOf(b),
	}
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	zlog := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.DebugLevel)
	if _, err := ccs.Solve(w, solver.WithLogger(zlog)); err != nil {
		t.Fatalf("solve add: %v", err)
	}
}
