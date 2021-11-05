package bip32

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
)

var testVectors []vector

//go:embed testdata/vectors.json
var vectors []byte

func TestVectors(t *testing.T) {
	for _, test := range testVectors {
		privKey, err := NewMasterKey(test.seed)
		if err != nil {
			t.Fatal(err)
		}
		if k := privKey.String(); k != test.privateKey {
			t.Fatal(k, test.privateKey)
		}

		{
			ser, err := privKey.Serialize()
			if err != nil {
				t.Error(err)
			}
			if _, err := Deserialize(ser); err != nil {
				t.Error(err)
			}
		}

		pubKey := privKey.PublicKey()
		if k := pubKey.String(); k != test.publicKey {
			t.Fatal(k, test.publicKey)
		}

		{
			ser, err := pubKey.Serialize()
			if err != nil {
				t.Error(err)
			}
			if _, err := Deserialize(ser); err != nil {
				t.Error(err)
			}
		}

		for _, c := range test.children {
			privKey, _ := NewMasterKey(test.seed)
			for _, p := range c.path {
				privKey, err = privKey.NewChildKey(p)
				if err != nil {
					t.Error(p, privKey)
					continue
				}
			}

			if d := privKey.Depth[0]; d != byte(len(c.path)) {
				t.Error(d, c.path)
			}
			if k := privKey.String(); k != c.privateKey {
				t.Fatal(k, c.privateKey)
			}
		}
	}
}

func init() {
	var vs []struct {
		Seed       string
		PublicKey  string
		PrivateKey string
		Children   []struct {
			PublicKey  string
			PrivateKey string
			Path       []string
		}
	}
	if err := json.Unmarshal(vectors, &vs); err != nil {
		panic(err)
	}
	for _, v := range vs {
		seed, err := hex.DecodeString(v.Seed)
		if err != nil {
			panic(err)
		}
		var children []childVector
		for _, c := range v.Children {
			var path []uint32
			for _, p := range c.Path {
				h, err := hex.DecodeString(p)
				if err != nil {
					panic(err)
				}
				path = append(path, binary.BigEndian.Uint32(h))
			}
			children = append(children, childVector{
				publicKey:  c.PublicKey,
				privateKey: c.PrivateKey,
				path:       path,
			})
		}
		testVectors = append(testVectors, vector{
			seed:       seed,
			publicKey:  v.PublicKey,
			privateKey: v.PrivateKey,
			children:   children,
		})
	}
}

type childVector struct {
	privateKey string
	publicKey  string
	path       []uint32
}

type vector struct {
	seed       []byte
	privateKey string
	publicKey  string
	children   []childVector
}
