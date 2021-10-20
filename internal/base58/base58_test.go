package base58

import (
	"testing"
)

func TestEncode(t *testing.T) {
	for _, test := range []struct {
		decoded string
		encoded string
	}{
		{"", ""},
		{" ", "Z"},
		{"0", "q"},
		{"abc", "ZiCa"},
		{"1234598760", "3mJr7AoUXx2Wqd"},
	} {
		e := BitcoinEncoding.Encode([]byte(test.decoded))
		if e := string(e); e != test.encoded {
			t.Errorf("Expected %q, got %q", test.encoded, e)
		}
		d, err := BitcoinEncoding.Decode(e)
		if err != nil {
			t.Error(err)
		}
		if d := string(d); d != test.decoded {
			t.Errorf("Expected %q, got %q", test.decoded, d)
		}
	}
}
