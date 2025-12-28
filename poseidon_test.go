package poseidon377

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	gposeidon "github.com/vocdoni/poseidon377/gnark/poseidon377"
)

func mustElement(t *testing.T, s string) fr.Element {
	t.Helper()
	var e fr.Element
	if _, err := e.SetString(s); err != nil {
		t.Fatalf("parse element: %v", err)
	}
	return e
}

func TestPenumbraVectors(t *testing.T) {
	domain := DomainFromLEBytes([]byte("Penumbra_TestVec")) // domain from docs/test_vectors.md
	inputs := []fr.Element{
		mustElement(t, "7553885614632219548127688026174585776320152166623257619763178041781456016062"),
		mustElement(t, "2337838243217876174544784248400816541933405738836087430664765452605435675740"),
		mustElement(t, "4318449279293553393006719276941638490334729643330833590842693275258805886300"),
		mustElement(t, "2884734248868891876687246055367204388444877057000108043377667455104051576315"),
		mustElement(t, "5235431038142849831913898188189800916077016298531443239266169457588889298166"),
		mustElement(t, "66948599770858083122195578203282720327054804952637730715402418442993895152"),
	}
	expected := []fr.Element{
		inputs[1],
		inputs[2],
		inputs[3],
		inputs[4],
		inputs[5],
		mustElement(t, "6797655301930638258044003960605211404784492298673033525596396177265014216269"),
	}

	out1, err := Hash1(domain, inputs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !out1.Equal(&expected[0]) {
		t.Fatalf("hash1 mismatch\nexpected %s\ngot      %s", expected[0].String(), out1.String())
	}

	out2, err := Hash2(domain, inputs[0], inputs[1])
	if err != nil {
		t.Fatal(err)
	}
	if !out2.Equal(&expected[1]) {
		t.Fatalf("hash2 mismatch\nexpected %s\ngot      %s", expected[1].String(), out2.String())
	}

	out3, err := Hash3(domain, inputs[0], inputs[1], inputs[2])
	if err != nil {
		t.Fatal(err)
	}
	if !out3.Equal(&expected[2]) {
		t.Fatalf("hash3 mismatch\nexpected %s\ngot      %s", expected[2].String(), out3.String())
	}

	out4, err := Hash4(domain, inputs[0], inputs[1], inputs[2], inputs[3])
	if err != nil {
		t.Fatal(err)
	}
	if !out4.Equal(&expected[3]) {
		t.Fatalf("hash4 mismatch\nexpected %s\ngot      %s", expected[3].String(), out4.String())
	}

	out5, err := Hash5(domain, inputs[0], inputs[1], inputs[2], inputs[3], inputs[4])
	if err != nil {
		t.Fatal(err)
	}
	if !out5.Equal(&expected[4]) {
		t.Fatalf("hash5 mismatch\nexpected %s\ngot      %s", expected[4].String(), out5.String())
	}

	out6, err := Hash6(domain, inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5])
	if err != nil {
		t.Fatal(err)
	}
	if !out6.Equal(&expected[5]) {
		t.Fatalf("hash6 mismatch\nexpected %s\ngot      %s", expected[5].String(), out6.String())
	}
}

// Circuit that hashes three limbs and checks against an expected native result.
type poseidonCircuit struct {
	Domain   frontend.Variable
	Inputs   [3]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *poseidonCircuit) Define(api frontend.API) error {
	out, err := gposeidon.Hash(api, c.Domain, c.Inputs[0], c.Inputs[1], c.Inputs[2])
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, c.Expected)
	return nil
}

func TestCircuitMatchesNative(t *testing.T) {
	assert := test.NewAssert(t)

	domain := DomainFromLEBytes([]byte("Penumbra_TestVec"))
	i1 := mustElement(t, "7553885614632219548127688026174585776320152166623257619763178041781456016062")
	i2 := mustElement(t, "2337838243217876174544784248400816541933405738836087430664765452605435675740")
	i3 := mustElement(t, "4318449279293553393006719276941638490334729643330833590842693275258805886300")

	native, err := Hash3(domain, i1, i2, i3)
	if err != nil {
		t.Fatal(err)
	}

	witness := poseidonCircuit{
		Domain:   domain,
		Inputs:   [3]frontend.Variable{i1, i2, i3},
		Expected: native,
	}

	assert.ProverSucceeded(
		&poseidonCircuit{},
		&witness,
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16),
	)
}

func TestConstraintCounts(t *testing.T) {
	ccs1, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &countCircuit1{})
	if err != nil {
		t.Fatalf("compile rate1: %v", err)
	}
	ccs2, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &countCircuit2{})
	if err != nil {
		t.Fatalf("compile rate2: %v", err)
	}
	ccs3, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &countCircuit3{})
	if err != nil {
		t.Fatalf("compile rate3: %v", err)
	}
	ccs6, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &countCircuit6{})
	if err != nil {
		t.Fatalf("compile rate6: %v", err)
	}
	ccs7, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &countCircuit7{})
	if err != nil {
		t.Fatalf("compile rate6: %v", err)
	}

	t.Logf("rate-1 constraints: %d", ccs1.GetNbConstraints())
	t.Logf("rate-2 constraints: %d", ccs2.GetNbConstraints())
	t.Logf("rate-3 constraints: %d", ccs3.GetNbConstraints())
	t.Logf("rate-6 constraints: %d", ccs6.GetNbConstraints())
	t.Logf("rate-7 constraints: %d", ccs7.GetNbConstraints())
}

type countCircuit1 struct {
	Domain frontend.Variable
	A      frontend.Variable
}

func (c *countCircuit1) Define(api frontend.API) error {
	out, err := gposeidon.Hash(api, c.Domain, c.A)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, out)
	return nil
}

type countCircuit2 struct {
	Domain frontend.Variable
	A      frontend.Variable
	B      frontend.Variable
}

func (c *countCircuit2) Define(api frontend.API) error {
	out, err := gposeidon.Hash(api, c.Domain, c.A, c.B)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, out)
	return nil
}

type countCircuit3 struct {
	Domain frontend.Variable
	A      frontend.Variable
	B      frontend.Variable
	C      frontend.Variable
}

func (c *countCircuit3) Define(api frontend.API) error {
	out, err := gposeidon.Hash(api, c.Domain, c.A, c.B, c.C)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, out)
	return nil
}

type countCircuit6 struct {
	Domain frontend.Variable
	Inputs [6]frontend.Variable
}

func (c *countCircuit6) Define(api frontend.API) error {
	out, err := gposeidon.Hash(api,
		c.Domain,
		c.Inputs[0], c.Inputs[1], c.Inputs[2],
		c.Inputs[3], c.Inputs[4], c.Inputs[5],
	)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, out)
	return nil
}

type countCircuit7 struct {
	Domain frontend.Variable
	Inputs [7]frontend.Variable
}

func (c *countCircuit7) Define(api frontend.API) error {
	out, err := gposeidon.Hash(api,
		c.Domain,
		c.Inputs[0], c.Inputs[1], c.Inputs[2],
		c.Inputs[3], c.Inputs[4], c.Inputs[5],
		c.Inputs[6],
	)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, out)
	return nil
}

// Multi-hash large input tests ------------------------------------------------

type multiCircuit16 struct {
	Domain   frontend.Variable
	Inputs   [16]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *multiCircuit16) Define(api frontend.API) error {
	out, err := gposeidon.MultiHash(api, c.Domain, c.Inputs[:]...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, c.Expected)
	return nil
}

type multiCircuit32 struct {
	Domain   frontend.Variable
	Inputs   [32]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *multiCircuit32) Define(api frontend.API) error {
	out, err := gposeidon.MultiHash(api, c.Domain, c.Inputs[:]...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, c.Expected)
	return nil
}

type multiCircuit64 struct {
	Domain   frontend.Variable
	Inputs   [64]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *multiCircuit64) Define(api frontend.API) error {
	out, err := gposeidon.MultiHash(api, c.Domain, c.Inputs[:]...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, c.Expected)
	return nil
}

type multiCircuit128 struct {
	Domain   frontend.Variable
	Inputs   [128]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *multiCircuit128) Define(api frontend.API) error {
	out, err := gposeidon.MultiHash(api, c.Domain, c.Inputs[:]...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, c.Expected)
	return nil
}

type multiCircuit256 struct {
	Domain   frontend.Variable
	Inputs   [256]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *multiCircuit256) Define(api frontend.API) error {
	out, err := gposeidon.MultiHash(api, c.Domain, c.Inputs[:]...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, c.Expected)
	return nil
}

func TestMultiHashLargeMatchesCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	domain := DomainFromLEBytes([]byte("Penumbra_TestVec"))

	cases := []struct {
		name    string
		size    int
		builder func() (frontend.Circuit, frontend.Circuit)
	}{
		{
			name: "16",
			size: 16,
			builder: func() (frontend.Circuit, frontend.Circuit) {
				return &multiCircuit16{}, &multiCircuit16{}
			},
		},
		{
			name: "32",
			size: 32,
			builder: func() (frontend.Circuit, frontend.Circuit) {
				return &multiCircuit32{}, &multiCircuit32{}
			},
		},
		{
			name: "64",
			size: 64,
			builder: func() (frontend.Circuit, frontend.Circuit) {
				return &multiCircuit64{}, &multiCircuit64{}
			},
		},
		{
			name: "128",
			size: 128,
			builder: func() (frontend.Circuit, frontend.Circuit) {
				return &multiCircuit128{}, &multiCircuit128{}
			},
		},
		{
			name: "256",
			size: 256,
			builder: func() (frontend.Circuit, frontend.Circuit) {
				return &multiCircuit256{}, &multiCircuit256{}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			inputs := make([]fr.Element, tc.size)
			for i := range inputs {
				inputs[i].SetUint64(uint64(i + 1))
			}

			native, err := MultiHash(domain, inputs...)
			if err != nil {
				t.Fatalf("native multihash %s: %v", tc.name, err)
			}

			var witness frontend.Circuit
			empty, wit := tc.builder()

			switch w := wit.(type) {
			case *multiCircuit16:
				w.Domain = domain
				for i := range inputs {
					w.Inputs[i] = inputs[i]
				}
				w.Expected = native
				witness = w
			case *multiCircuit32:
				w.Domain = domain
				for i := range inputs {
					w.Inputs[i] = inputs[i]
				}
				w.Expected = native
				witness = w
			case *multiCircuit64:
				w.Domain = domain
				for i := range inputs {
					w.Inputs[i] = inputs[i]
				}
				w.Expected = native
				witness = w
			case *multiCircuit128:
				w.Domain = domain
				for i := range inputs {
					w.Inputs[i] = inputs[i]
				}
				w.Expected = native
				witness = w
			case *multiCircuit256:
				w.Domain = domain
				for i := range inputs {
					w.Inputs[i] = inputs[i]
				}
				w.Expected = native
				witness = w
			default:
				t.Fatalf("unsupported circuit type")
			}

			ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, empty)
			if err != nil {
				t.Fatalf("compile %s: %v", tc.name, err)
			}
			t.Logf("multihash-%s constraints: %d", tc.name, ccs.GetNbConstraints())

			assert.ProverSucceeded(
				empty,
				witness,
				test.WithCurves(ecc.BLS12_377),
				test.WithBackends(backend.GROTH16),
			)
		})
	}
}
