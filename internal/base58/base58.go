package base58

import (
	"bytes"
	"fmt"
	"math/big"
)

var (
	BitcoinEncoding = New([]byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"))

	bigRadix = [...]*big.Int{
		big.NewInt(0),
		big.NewInt(58),
		big.NewInt(58 * 58),
		big.NewInt(58 * 58 * 58),
		big.NewInt(58 * 58 * 58 * 58),
		big.NewInt(58 * 58 * 58 * 58 * 58),
		big.NewInt(58 * 58 * 58 * 58 * 58 * 58),
		big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58),
		big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
		big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
		big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58), // 58^10
	}
)

func Decode(b []byte) ([]byte, error) {
	return BitcoinEncoding.Decode(b)
}

func Encode(b []byte) []byte {
	return BitcoinEncoding.Encode(b)
}

type Encoding struct {
	encodeMap [58]byte
	decodeMap [256]int64
}

func New(encodeMap []byte) *Encoding {
	enc := &Encoding{}
	copy(enc.encodeMap[:], encodeMap)
	for i := range enc.decodeMap {
		enc.decodeMap[i] = -1
	}
	for i, b := range enc.encodeMap {
		enc.decodeMap[b] = int64(i)
	}
	return enc
}

func (e Encoding) Decode(b []byte) ([]byte, error) {
	data := b
	n, mod := new(big.Int), new(big.Int)
	for 0 < len(data) {
		l := len(data)
		if 10 < l {
			l = 10
		}

		var t uint64 = 0
		for _, b := range data[:l] {
			tmp := e.decodeMap[b]
			if tmp == 255 {
				return nil, fmt.Errorf("invalid char: %c", b)
			}
			t = t*58 + uint64(tmp)
		}
		n = n.Mul(n, bigRadix[l])
		mod = mod.SetUint64(t)
		n = n.Add(n, mod)
		data = data[l:]
	}
	return n.Bytes(), nil
}

func (e Encoding) Encode(b []byte) []byte {
	data := new(bytes.Buffer)
	n, mod := new(big.Int), new(big.Int)
	n.SetBytes(b)
	for 0 < n.Sign() {
		// n, mod = n / 58, n % 58
		n, mod = n.DivMod(n, bigRadix[10], mod)
		m := mod.Int64()
		if n.Sign() == 0 {
			for 0 < m {
				data.WriteByte(e.encodeMap[m%58])
				m /= 58
			}
			continue
		}
		for i := 0; i < 10; i++ {
			data.WriteByte(e.encodeMap[m%58])
			m /= 58
		}
	}

	var (
		bs = data.Bytes()
		l  = len(bs)
	)
	for i := 0; i < l/2; i++ {
		bs[i], bs[l-1-i] = bs[l-1-i], bs[i]
	}

	return bs
}
