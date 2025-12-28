package poseidon377

import "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"

func Hash1(domain fr.Element, v fr.Element) (fr.Element, error) {
	return Hash(domain, v)
}

func Hash2(domain fr.Element, a, b fr.Element) (fr.Element, error) {
	return Hash(domain, a, b)
}

func Hash3(domain fr.Element, a, b, c fr.Element) (fr.Element, error) {
	return Hash(domain, a, b, c)
}

func Hash4(domain fr.Element, a, b, c, d fr.Element) (fr.Element, error) {
	return Hash(domain, a, b, c, d)
}

func Hash5(domain fr.Element, a, b, c, d, e fr.Element) (fr.Element, error) {
	return Hash(domain, a, b, c, d, e)
}

func Hash6(domain fr.Element, a, b, c, d, e, f fr.Element) (fr.Element, error) {
	return Hash(domain, a, b, c, d, e, f)
}

func Hash7(domain fr.Element, a, b, c, d, e, f, g fr.Element) (fr.Element, error) {
	return Hash(domain, a, b, c, d, e, f, g)
}
