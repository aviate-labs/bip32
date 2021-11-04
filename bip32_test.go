package bip32

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"reflect"
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
			des, err := Deserialize(ser)
			if err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(privKey, des) {
				t.Error(privKey, des)
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
