package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/aviate-labs/bip32/internal/base58"
	"github.com/aviate-labs/secp256k1"
)

var (
	curve = secp256k1.S256()
)

func checksum(data []byte) ([]byte, error) {
	hasher := sha256.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, bytes.ErrTooLarge
	}
	data = hasher.Sum(nil)
	hasher = sha256.New()
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

	IsPublic bool // Internal use.
}

func (k Key) PublicKey() Key {
	if k.IsPublic {
		return k
	}

	// Compress.
	x, y := curve.ScalarBaseMult(k.KeyData[:])
	var buffer bytes.Buffer
	buffer.WriteByte(byte(0x2) + byte(y.Bit(0)))
	bs := x.Bytes()
	for i := 0; i < (33 - 1 - len(bs)); i++ {
		buffer.WriteByte(0x0)
	}
	buffer.Write(bs)

	var keyData [33]byte
	copy(keyData[:], buffer.Bytes())

	return Key{
		Version:     [4]byte{0x04, 0x88, 0xB2, 0x1E},
		Depth:       k.Depth,
		ChildNumber: k.ChildNumber,
		FingerPrint: k.FingerPrint,
		ChainCode:   k.ChainCode,
		KeyData:     keyData,
		IsPublic:    true,
	}
}

func Deserialize(data []byte) (Key, error) {
	if len(data) != 82 {
		return Key{}, fmt.Errorf("invalid key length")
	}

	var key Key
	copy(key.Version[:], data[:4])
	copy(key.Depth[:], data[4:5])
	copy(key.FingerPrint[:], data[5:9])
	copy(key.ChildNumber[:], data[9:13])
	copy(key.ChainCode[:], data[13:45])
	copy(key.KeyData[:], data[45:78])
	if data[45] != 0 {
		key.IsPublic = true
	}

	// Validation.
	actual := data[len(data)-4:]
	expected, err := checksum(data[:len(data)-4])
	if err != nil {
		return Key{}, err
	}
	for i := range actual {
		if actual[i] != expected[i] {
			return Key{}, fmt.Errorf("invalid checksum")
		}
	}

	return key, nil
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
