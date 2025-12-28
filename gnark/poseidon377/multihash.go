package poseidon377

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

const (
	maxRate            = 7
	MaxMultiHashInputs = 256
)

// MultiHash hashes an arbitrary-length list of field elements by chunking with the highest available rate (7).
// Domain is placed in the capacity slot on every chunk. Supports up to MaxMultiHashInputs inputs.
func MultiHash(api frontend.API, domain frontend.Variable, inputs ...frontend.Variable) (frontend.Variable, error) {
	if len(inputs) == 0 {
		var zero frontend.Variable
		return zero, fmt.Errorf("poseidon377: need at least 1 limb")
	}
	if len(inputs) > MaxMultiHashInputs {
		var zero frontend.Variable
		return zero, fmt.Errorf("poseidon377: too many inputs (%d > %d)", len(inputs), MaxMultiHashInputs)
	}

	current := make([]frontend.Variable, len(inputs))
	copy(current, inputs)

	for len(current) > maxRate {
		next := make([]frontend.Variable, 0, (len(current)+maxRate-1)/maxRate)
		for i := 0; i < len(current); i += maxRate {
			end := i + maxRate
			if end > len(current) {
				end = len(current)
			}
			h, err := Hash(api, domain, current[i:end]...)
			if err != nil {
				var zero frontend.Variable
				return zero, err
			}
			next = append(next, h)
		}
		current = next
	}

	return Hash(api, domain, current...)
}
