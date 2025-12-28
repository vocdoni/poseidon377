package params

import "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"

// Alpha captures the Poseidon S-box exponent.
type Alpha struct {
	Exponent uint32
	Inverse  bool
}

// Parameters bundles all constants needed by the permutation.
type Parameters struct {
	M             int
	StateSize     int
	FullRounds    int
	PartialRounds int
	Alpha         Alpha

	Arc          []fr.Element
	OptimizedArc []fr.Element
	MDS          []fr.Element

	OptimizedMDS OptimizedMDS
}

// OptimizedMDS encodes the optimized matrices described in the Penumbra Poseidon implementation.
type OptimizedMDS struct {
	MHat         []fr.Element
	V            []fr.Element
	W            []fr.Element
	MPrime       []fr.Element
	MDoublePrime []fr.Element
	MInverse     []fr.Element
	MHatInverse  []fr.Element
	M00          fr.Element
	MI           []fr.Element

	VCollection    []fr.Element
	WHatCollection []fr.Element
}

// FromMontgomery builds an fr.Element from Montgomery-form limbs.
func FromMontgomery(limbs [4]uint64) fr.Element {
	return fr.Element{limbs[0], limbs[1], limbs[2], limbs[3]}
}
