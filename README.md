# Poseidon377

Pure Go and Gnark Poseidon hash implementation for the BLS12-377 scalar field.

- Based on the Penumbra implementation: https://github.com/penumbra-zone/poseidon377
- Documentation overview: see `docs/README.md` (mirrors https://protocol.penumbra.zone/main/crypto/poseidon.html).

## Requirements

- Go 1.25.x

## Go Native API

```go
import (
  "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
  poseidon "github.com/vocdoni/poseidon377"
)

func example() (fr.Element, error) {
  domain := poseidon.DomainFromLEBytes([]byte("example"))
  var a, b fr.Element
  a.SetUint64(1)
  b.SetUint64(2)
  return poseidon.Hash(domain, a, b) // rate = len(inputs), supported rates: 1..7
}
```

Rate-specific helpers: `Hash1`...`Hash7`.

**Rate** is the number of message limbs absorbed in one permutation call; the state width is `rate + 1` (the extra limb is capacity/domain). Choose `HashN` where `N = rate` equals your input length.

## Gnark Gadget

```go
import (
  "github.com/consensys/gnark/frontend"
  "github.com/vocdoni/poseidon377/gnark/poseidon377"
)

type Circuit struct {
  Domain frontend.Variable
  A, B   frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
  out, err := poseidon377.Hash(api, c.Domain, c.A, c.B) // rate=2
  if err != nil {
    return err
  }
  api.AssertIsEqual(out, out)
  return nil
}
```

## Emulated Gnark Gadget

Useful when combining BLS12-377 with BW6-761 for recursive proofs.

```go
type Circuit struct {
  Domain emulated.Element[poseidon377.FrParams]
  Inputs [3]emulated.Element[poseidon377.FrParams]
}
func (c *Circuit) Define(api frontend.API) error {
  out, err := poseidon377.Hash(api, c.Domain, c.Inputs[:]...)
  if err != nil { return err }
  field, _ := emulated.NewField[poseidon377.FrParams](api)
  field.AssertIsEqual(&out, &c.Inputs[0]) // replace with your expected digest
  return nil
}
```

## Multi-Input Hashing

- `MultiHash(domain, inputs...)` (Go) and `MultiHash(api, domain, inputs...)` (gnark) hash up to 256 field elements by chunking with the highest available rate (7) and re-hashing chunk outputs until one result remains. Domain is placed in the capacity slot at every chunk level. This tree-style hashing is built from the same fixed-width parameters.
- Go example:
  ```go
  domain := poseidon.DomainFromLEBytes([]byte("example"))
  inputs := make([]fr.Element, 32)
  for i := range inputs { inputs[i].SetUint64(uint64(i+1)) }
  out, err := poseidon.MultiHash(domain, inputs...)
  ```
- Gnark example:
  ```go
  type Circuit struct {
    Domain frontend.Variable
    Inputs [32]frontend.Variable
  }
  func (c *Circuit) Define(api frontend.API) error {
    out, err := gposeidon.MultiHash(api, c.Domain, c.Inputs[:]...)
    if err != nil { return err }
    api.AssertIsEqual(out, out)
    return nil
  }
  ```

## Constraints

Constraint counts native (Groth16, r1cs builder):
- rate-1: 236
- rate-2: 276
- rate-3: 316
- rate-6: 436
- rate-7: 476

Multi-hash (treeed with rate-7 chunks) constraint counts (Groth16, r1cs builder):
- Native gadget on BLS12-377:
  - 16 inputs: 1,541  (~96.3 constraints/input)
  - 32 inputs: 2,651  (~82.8 constraints/input)
  - 64 inputs: 5,576  (~87.1 constraints/input)
  - 128 inputs: 10,486 (~81.9 constraints/input)
  - 256 inputs: 20,541 (~80.2 constraints/input)
- Emulated gadget on BW6-761 host:
  - 16 inputs: 333,066 (~20,817 constraints/input)
  - 32 inputs: 571,680 (~17,865 constraints/input)
  - 64 inputs: 1,124,750 (~17,574 constraints/input)
  - 128 inputs: 2,129,257 (~16,636 constraints/input)
  - 256 inputs: 4,171,911 (~16,218 constraints/input)

## Tests

Run all tests:

```
go test ./...
```

What’s covered:
- Penumbra vector checks for rates 1–6.
- Native vs gnark circuit equivalence.
- Constraint counts per rate (`TestConstraintCounts`).
- Multi-hash equivalence on 16, 32, 64, 128, 256 inputs (native and emulated gadgets, Groth16).


## Safety and Compatibility Notes

- Matches Penumbra’s optimized schedule: same full/partial round ordering, optimized ARC, $M_i$ then sparse $v/ŵ$ with M00, $x^17$ S-box only.
- Parameters are generated from Penumbra’s audited constants (test vectors (rates 1–6) pass).
- Alpha inverse is rejected (only α=17 supported in these params).
- Only optimized path is exposed (unoptimized path not provided).
- Supported rates are 1–7 (Penumbra only generated parameters up to width 8); higher rates would require new parameter generation and security review.

