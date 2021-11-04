package bip32

import (
	"bytes"
	"crypto/sha256"

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

func private2public(data [33]byte) [33]byte {
	x, y := curve.ScalarBaseMult(data[:])
	var buffer bytes.Buffer
	buffer.WriteByte(byte(0x2) + byte(y.Bit(0)))
	bs := x.Bytes()
	for i := 0; i < (33 - 1 - len(bs)); i++ {
		buffer.WriteByte(0x0)
	}
	buffer.Write(bs)

	var keyData [33]byte
	copy(keyData[:], buffer.Bytes())
	return keyData
}
