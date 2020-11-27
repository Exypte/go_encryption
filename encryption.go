package go_encryption

import (
	"log"
	"math/big"
	"crypto/rand"
	"math"
	"bytes"
)

type privateKey struct {
	n *big.Int
	u *big.Int
}

type publicKey struct {
	n *big.Int
	e *big.Int
	m *big.Int
}

func CouplePublic(numBit int) publicKey{

	p, err := rand.Prime(rand.Reader, int(math.Pow(float64(2), float64(numBit))))

	if err != nil{
		log.Fatal(err.Error())
	}

	q, err := rand.Prime(rand.Reader, int(math.Pow(float64(2), float64(numBit))))

	if err != nil{
		log.Fatal(err.Error())
	}

	for {
		if p.Cmp(q) == 0 {
			q, err = rand.Prime(rand.Reader, numBit)

			if err != nil{
				log.Fatal(err.Error())
			}
		} else {
			break
		}
	}

	p_substract := big.NewInt(0).Sub(p, big.NewInt(1))
	q_substract := big.NewInt(0).Sub(q, big.NewInt(1))

	n := big.NewInt(0).Mul(p, q)
	m := big.NewInt(0).Mul(p_substract, q_substract)

	e, err := rand.Prime(rand.Reader, int(math.Pow(float64(2), float64(numBit / 2))))

	if err != nil{
		log.Fatal(err.Error())
	}

	for {
		if big.NewInt(0).GCD(nil, nil, m, e).Cmp(big.NewInt(1)) != 0 {
			e, err = rand.Prime(rand.Reader, int(math.Pow(float64(2), float64(numBit / 2))))

			if err != nil{
				log.Fatal(err.Error())
			}
		} else {
			break
		}
	}

	pk := publicKey{n: n, m: m, e: e}

	return pk
}

func AlgoEuclide(pubKey *publicKey) *big.Int{
	r := []*big.Int{pubKey.e, pubKey.m}
	u := []*big.Int{big.NewInt(1), big.NewInt(0)}
	v := []*big.Int{big.NewInt(0), big.NewInt(1)}

	for {
		if r[len(r) - 1].Cmp(big.NewInt(0)) != 0 {
			r1 := r[len(r) - 1]
			r2 := r[len(r) - 2]
			u1 := u[len(u) - 1]
			u2 := u[len(u) - 2]
			v1 := v[len(v) - 1]
			v2 := v[len(v) - 2]

			r = append(r, big.NewInt(0).Sub(r2, big.NewInt(0).Mul(big.NewInt(0).Div(r2, r1), r1)))
			u = append(u, big.NewInt(0).Sub(u2, big.NewInt(0).Mul(big.NewInt(0).Div(r2, r1), u1)))
			v = append(v, big.NewInt(0).Sub(v2, big.NewInt(0).Mul(big.NewInt(0).Div(r2, r1), v1)))
		}else{
			break
		}
	}

	return u[len(u) - 2]
}

func CouplePrivate(pubKey *publicKey) privateKey{
	m := pubKey.m
	uFinal := AlgoEuclide(pubKey)
	k := big.NewInt(-1)

	for{
		if !(big.NewInt(2).Cmp(uFinal) == -1 && uFinal.Cmp(m) == -1){
			uFinal = big.NewInt(0).Sub(uFinal, big.NewInt(0).Mul(k, m))
			k = big.NewInt(0).Sub(k, big.NewInt(1))
		}else{
			break
		}
	}

	return privateKey{n: pubKey.n,u: uFinal}
}

func Encryption(msg string, pubKey *publicKey) []*big.Int{
	var ascii []*big.Int

	runes := []rune(msg)

	for i := 0; i < len(runes); i++{
		ascii_code := int64(runes[i])

		big_ascii := big.NewInt(ascii_code)

		ascii = append(ascii, big.NewInt(0).Exp(big_ascii, pubKey.e, pubKey.n))
	}

	return ascii
}

func Decryption(msg []*big.Int, priKey *privateKey) string{
	var str bytes.Buffer

	for i := 0; i < len(msg); i++{
		ascii := big.NewInt(0).Exp(msg[i], priKey.u, priKey.n)
		char := rune(ascii.Uint64())
		str.WriteString(string(char))
	}

	return str.String()
}