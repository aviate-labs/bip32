package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/aviate-labs/bip32/internal/base58"
)

func checksum(data []byte) ([]byte, error) {
	hasher := sha256.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, bytes.ErrTooLarge
	}
	data = hasher.Sum(nil)
	if _, err := hasher.Write(data); err != nil {
		return nil, bytes.ErrTooLarge
	}
	return hasher.Sum(nil)[:4], nil
}

type Key struct {
	// Version bytes.
	Version [4]byte
	// Depth, 0x00 for master nodes, 0x01 for level-1 derived keys, ...
	Depth [1]byte
	// Fingerprint of the parent's key (0x00000000 if master key).
	FingerPrint [4]byte
	// Child number (0x00000000 if master key).
	ChildNumber [4]byte
	// Chain code.
	ChainCode [32]byte
	// KeyData for the public/private key.
	KeyData [33]byte
}

// A seed sequence between 128 and 512 bits; 256 bits is advised.
func NewMasterKey(seed []byte) (Key, error) {
	var (
		key   [33]byte
		chain [32]byte
	)
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	if _, err := hmac.Write(seed); err != nil {
		return Key{}, err
	}
	i := hmac.Sum(nil)
	copy(key[1:], i[:32])
	copy(chain[:], i[32:])

	return Key{
		Version:     [4]byte{0x04, 0x88, 0xAD, 0xE4},
		Depth:       [1]byte{0x00},
		FingerPrint: [4]byte{0x00, 0x00, 0x00, 0x00},
		ChildNumber: [4]byte{0x00, 0x00, 0x00, 0x00},
		ChainCode:   chain,
		KeyData:     key,
	}, nil
}

func (k Key) Serialize() ([]byte, error) {
	buffer := new(bytes.Buffer)
	buffer.Write(k.Version[:])
	buffer.WriteByte(k.Depth[0])
	buffer.Write(k.FingerPrint[:])
	buffer.Write(k.ChildNumber[:])
	buffer.Write(k.ChainCode[:])
	buffer.Write(k.KeyData[:])
	bs := buffer.Bytes()
	cs, err := checksum(bs)
	if err != nil {
		return nil, err
	}
	return append(bs, cs...), nil
}

func (k Key) String() string {
	raw, _ := k.Serialize()
	return string(base58.Encode(raw))
}
