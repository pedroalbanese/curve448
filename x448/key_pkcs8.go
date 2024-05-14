package x448

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	// ECDH
	oidPublicKeyX448 = asn1.ObjectIdentifier{1, 3, 101, 111}
)

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func MarshalPublicKey(key PublicKey) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier

	publicKeyAlgorithm.Algorithm = oidPublicKeyX448

	publicKeyBytes = key

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	return asn1.Marshal(pkix)
}

func ParsePublicKey(derBytes []byte) (pub PublicKey, err error) {
	var pki publicKeyInfo
	rest, err := asn1.Unmarshal(derBytes, &pki)
	if err != nil {
		return
	}

	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}

	algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyX448)
	if !algoEq {
		err = errors.New("x448: unknown public key algorithm")
		return
	}

	// Þºúµ×É
	keyData := &pki

	publicKeyBytes := []byte(keyData.PublicKey.RightAlign())

	return PublicKey(publicKeyBytes), nil
}

func MarshalPrivateKey(key PrivateKey) ([]byte, error) {
	var privKey pkcs8

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyX448,
	}

	curvePrivateKey, err := asn1.Marshal(key.Seed())
	if err != nil {
		return nil, fmt.Errorf("x448: failed to marshal private key: %v", err)
	}

	privKey.PrivateKey = curvePrivateKey

	return asn1.Marshal(privKey)
}

func ParsePrivateKey(derBytes []byte) (PrivateKey, error) {
	var privKey pkcs8
	var err error

	_, err = asn1.Unmarshal(derBytes, &privKey)
	if err != nil {
		return nil, err
	}

	algoEq := privKey.Algo.Algorithm.Equal(oidPublicKeyX448)
	if !algoEq {
		err = errors.New("x448: unknown private key algorithm")
		return nil, err
	}

	var curvePrivateKey []byte
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
		return nil, fmt.Errorf("x448: invalid X448 private key: %v", err)
	}

	if l := len(curvePrivateKey); l != SeedSize {
		return nil, fmt.Errorf("x448: invalid X448 private key length: %d", l)
	}

	return NewKeyFromSeed(curvePrivateKey), nil
}
