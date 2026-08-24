package sstp

import "testing"

func TestCryptoBindingRoundTrip(t *testing.T) {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	value, err := CryptoBinding(HashSHA256, nonce, []byte("certificate DER"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 100 {
		t.Fatalf("length = %d", len(value))
	}
	if err := VerifyCryptoBinding(value, nonce, []byte("certificate DER"), nil); err != nil {
		t.Fatal(err)
	}
	value[99] ^= 1
	if err := VerifyCryptoBinding(value, nonce, []byte("certificate DER"), nil); err == nil {
		t.Fatal("tampered binding accepted")
	}
}
