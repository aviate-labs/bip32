package bip32

import (
	"crypto/sha256"

	"github.com/aviate-labs/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

func doubleHash256(data []byte) ([]byte, error) {
	data, err := hash256(data)
	if err != nil {
		return nil, err
	}
	return hash256(data)
}

func hash160(data []byte) ([]byte, error) {
	data, err := hash256(data)
	if err != nil {
		return nil, err
	}
	h := ripemd160.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func hash256(data []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func private2public(privateKey [32]byte) [33]byte {
	data := append([]byte{0x00}, privateKey[:]...)
	x, y := curve.ScalarBaseMult(data[:])
	pk := secp256k1.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	var keyData [33]byte
	copy(keyData[:], pk.SerializeCompressed())
	return keyData
}
