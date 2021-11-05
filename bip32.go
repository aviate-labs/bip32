package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/aviate-labs/bip32/internal/base58"
	"github.com/aviate-labs/secp256k1"
)

var (
	curve = secp256k1.S256()
)

func checksum(data []byte) ([]byte, error) {
	h, err := doubleHash256(data)
	if err != nil {
		return nil, err
	}
	return h[:4], nil
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
	PrivateKeyData [32]byte
	PublicKeyData  [33]byte

	IsPublic bool // Internal use.
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
	if data[45] != 0 {
		copy(key.PublicKeyData[:], data[45:78])
		key.IsPublic = true
	} else {
		copy(key.PrivateKeyData[:], data[46:78])
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
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	if _, err := hmac.Write(seed); err != nil {
		return Key{}, err
	}
	i := hmac.Sum(nil)
	var (
		key   [32]byte
		chain [32]byte
	)
	copy(key[:], i[:32])
	copy(chain[:], i[32:])

	return Key{
		Version:        [4]byte{0x04, 0x88, 0xAD, 0xE4},
		ChainCode:      chain,
		PrivateKeyData: key,
		PublicKeyData:  private2public(key),
	}, nil
}

func (k Key) NewChildKey(index uint32) (Key, error) {
	hardened := 0x80000000 <= index

	// hardened: hmac-sha512(0x00 || ser512(priv) || ser32(i))
	// normal:   hmac-sha512(ser512(pub) || ser32(i))
	data := make([]byte, 37)
	if hardened {
		copy(data[1:], k.PrivateKeyData[:])
	} else {
		copy(data[:], k.PublicKeyData[:])
	}
	binary.BigEndian.PutUint32(data[33:], index)
	var childNumber [4]byte
	copy(childNumber[:], data[33:])
	hmac := hmac.New(sha512.New, k.ChainCode[:])
	if _, err := hmac.Write(data); err != nil {
		return Key{}, err
	}
	i := hmac.Sum(nil)
	var chain [32]byte
	copy(chain[:], i[32:])

	if k.IsPublic {
		// TODO
	} else {
		var fingerprint [4]byte
		h, err := hash160(k.PublicKeyData[:])
		if err != nil {
			return Key{}, nil
		}
		copy(fingerprint[:], h)

		bi := new(big.Int).SetBytes(i[:32])
		bp := new(big.Int).SetBytes(k.PrivateKeyData[:])
		bi = bi.Add(bi, bp)
		bi = bi.Mod(bi, curve.N)

		bs := bi.Bytes()
		var key [32]byte
		copy(key[32-len(bs):], bs)

		return Key{
			Version:        k.Version,
			Depth:          [1]byte{k.Depth[0] + 1},
			ChildNumber:    childNumber,
			FingerPrint:    fingerprint,
			ChainCode:      chain,
			PrivateKeyData: key,
			PublicKeyData:  private2public(key),
			IsPublic:       k.IsPublic,
		}, nil
	}

	return k, nil
}

func (k Key) PublicKey() Key {
	if k.IsPublic {
		return k
	}

	return Key{
		Version:        [4]byte{0x04, 0x88, 0xB2, 0x1E},
		Depth:          k.Depth,
		ChildNumber:    k.ChildNumber,
		FingerPrint:    k.FingerPrint,
		ChainCode:      k.ChainCode,
		PrivateKeyData: k.PrivateKeyData,
		PublicKeyData:  k.PublicKeyData,
		IsPublic:       true,
	}
}

func (k Key) Serialize() ([]byte, error) {
	var data []byte
	if k.IsPublic {
		data = k.PublicKeyData[:]
	} else {
		data = append([]byte{0x00}, k.PrivateKeyData[:]...)
	}

	buffer := new(bytes.Buffer)
	buffer.Write(k.Version[:])
	buffer.WriteByte(k.Depth[0])
	buffer.Write(k.FingerPrint[:])
	buffer.Write(k.ChildNumber[:])
	buffer.Write(k.ChainCode[:])
	buffer.Write(data)
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
