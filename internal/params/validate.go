package params

import "fmt"

// Validate checks basic shape and sizes of the parameter set.
func Validate(p *Parameters) error {
	if p.Alpha.Inverse {
		return fmt.Errorf("poseidon377: unsupported inverse alpha")
	}
	if p.FullRounds%2 != 0 {
		return fmt.Errorf("poseidon377: full rounds must be even, got %d", p.FullRounds)
	}
	width := p.StateSize
	expectedRounds := (p.FullRounds + p.PartialRounds) * width
	if len(p.OptimizedArc) != expectedRounds {
		return fmt.Errorf("poseidon377: optimized arc length mismatch")
	}
	if len(p.Arc) != expectedRounds {
		return fmt.Errorf("poseidon377: arc length mismatch")
	}
	if len(p.MDS) != width*width {
		return fmt.Errorf("poseidon377: mds length mismatch")
	}
	if len(p.OptimizedMDS.MI) != width*width {
		return fmt.Errorf("poseidon377: M_i length mismatch")
	}
	if len(p.OptimizedMDS.MHat) != (width-1)*(width-1) {
		return fmt.Errorf("poseidon377: M_hat length mismatch")
	}
	if len(p.OptimizedMDS.V) != width-1 || len(p.OptimizedMDS.W) != width-1 {
		return fmt.Errorf("poseidon377: v/w length mismatch")
	}
	if len(p.OptimizedMDS.MPrime) != width*width || len(p.OptimizedMDS.MDoublePrime) != width*width || len(p.OptimizedMDS.MInverse) != width*width {
		return fmt.Errorf("poseidon377: dense optimized matrix length mismatch")
	}
	if len(p.OptimizedMDS.MHatInverse) != (width-1)*(width-1) {
		return fmt.Errorf("poseidon377: M_hat_inverse length mismatch")
	}
	expectedSparse := p.PartialRounds * (width - 1)
	if len(p.OptimizedMDS.VCollection) != expectedSparse || len(p.OptimizedMDS.WHatCollection) != expectedSparse {
		return fmt.Errorf("poseidon377: sparse collection length mismatch")
	}
	return nil
}
