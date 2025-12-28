# Poseidon377 Docs (from Penumbra)

These notes summarize the Penumbra Poseidon (Poseidon1 over BLS12-377) design and parameters. The original documentation lives at https://protocol.penumbra.zone/main/crypto/poseidon.html; the markdown files in this directory mirror that content for convenience.

## Design at a Glance

- Sponge width: `t = rate + 1` (capacity = 1 limb, domain separator goes in the capacity slot).
- S-box: `x^17` (no inverse S-box).
- Rounds: `R_F = 8` full, `R_P = 31` partial (HADES schedule: first `R_F/2`, then all partial, then last `R_F/2`).
- Matrices and arcs: Penumbra’s optimized ARC/MDS (sparse partial rounds with `M_i`, `v`, `ŵ`, `M00`).
- Field: BLS12-377 scalar field (`decaf377::Fq` in Penumbra, `fr` in gnark-crypto).

For an overview of the permutation layers, see `overview.md`. Parameter generation details are in `paramgen.md`.
