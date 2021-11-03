package bip32

import (
	_ "embed"
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
			t.Error(k, test.privateKey)
		}
	}
}

func init() {
	var vs [][]string
	if err := json.Unmarshal(vectors, &vs); err != nil {
		panic(err)
	}
	for _, v := range vs {
		seed, err := hex.DecodeString(v[0])
		if err != nil {
			panic(err)
		}
		testVectors = append(testVectors, vector{
			seed:       seed,
			publicKey:  v[1],
			privateKey: v[2],
		})
	}
}

type vector struct {
	seed       []byte
	privateKey string
	publicKey  string
}
