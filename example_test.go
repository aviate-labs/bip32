package bip32_test

import (
	"fmt"

	"github.com/aviate-labs/bip32"
)

func ExampleNewMasterKey() {
	// b := make([]byte, 32)
	// _, _ = rand.Read(b)
	seed := []byte{
		166, 163, 138, 168, 166, 42, 54, 219, 131, 185, 32, 101, 144, 52, 91, 106,
		18, 148, 14, 81, 227, 75, 241, 74, 98, 147, 79, 213, 102, 20, 206, 191,
	}
	k, _ := bip32.NewMasterKey(seed)
	fmt.Println(k)
	// Output:
	// xprv9s21ZrQH143K4U1PHAHHRecoiFSWoiN1Bmu5xYd1NuygpjFJqwaGK4CUb3p3t8SDAXz3UGunAMvVwV8G3EMY8AQ1Nh8mnf1LRNttTCg5Jtk
}

func ExampleWallet() {
	// "xprv9s21ZrQH143K4U1PHAHHRecoiFSWoiN1Bmu5xYd1NuygpjFJqwaGK4CUb3p3t8SDAXz3UGunAMvVwV8G3EMY8AQ1Nh8mnf1LRNttTCg5Jtk
	k, _ := bip32.NewMasterKey([]byte{
		166, 163, 138, 168, 166, 42, 54, 219, 131, 185, 32, 101, 144, 52, 91, 106,
		18, 148, 14, 81, 227, 75, 241, 74, 98, 147, 79, 213, 102, 20, 206, 191,
	})
	fmt.Println(k)

	// 1. Derive 'm/0H'.
	a0, _ := k.NewChildKey(0x80000000)
	fmt.Println(a0)

	// 2. External 'm/0H/0'.
	e, _ := a0.NewChildKey(0)
	fmt.Println(e)

	// 3. Internal 'm/0H/1'.
	i, _ := a0.NewChildKey(1)
	fmt.Println(i)

	// Accounts are now ready to use!

	// Output:
	// xprv9s21ZrQH143K4U1PHAHHRecoiFSWoiN1Bmu5xYd1NuygpjFJqwaGK4CUb3p3t8SDAXz3UGunAMvVwV8G3EMY8AQ1Nh8mnf1LRNttTCg5Jtk
	// xprv9tvquRFh4V8jQDZuVGekxDdPWYrnbKhBHmBzAhPPDomd11wwoHpvBKyFu9aKGM3ibhXXL2eXQQNp9J1xnbtrVsHxzJQMMuPggtnU7uSDhCn
	// xprv9w9JzxiLV34ewg4ximsrp2idAwb6Tho1UDbA9YHf9Fmv65QJrJFrgvcXmAUCVoVRH2DWMuP33apo8rHurgUErPh4Bn2dw9fBMpcuMedaoby
	// xprv9w9JzxiLV34ezBsBxrdN1BtviRjTqe4R96YGNTHrqub59cbhDMWLKurVUX3BmbBaWtEtTaa5CPCJN3j7Q2cASssxQetoBQMo1puZrZzCsRz
}
