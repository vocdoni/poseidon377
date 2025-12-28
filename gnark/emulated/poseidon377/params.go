package poseidon377

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"

	"github.com/vocdoni/poseidon377/internal/params"
)

// FrParams defines the emulated parameters for the BLS12-377 scalar field.
type FrParams = emparams.BLS12377Fr

func constElement(f *emulated.Field[FrParams], fe fr.Element) emulated.Element[FrParams] {
	return *f.NewElement(fe.BigInt(new(big.Int)))
}

// Convenience wrappers around the native parameter set.
func nativeParams(rate int) (*params.Parameters, error) {
	p, ok := params.AllParameters[rate]
	if !ok {
		return nil, fmt.Errorf("poseidon377: unsupported rate %d", rate)
	}
	return p, nil
}
