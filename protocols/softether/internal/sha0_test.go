package softether

import (
	"encoding/hex"
	"testing"
)

func TestSHA0Vectors(t *testing.T) {
	for input, want := range map[string]string{
		"":    "f96cea198ad1dd5617ac084a3d92c6107708c0ef",
		"abc": "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880",
	} {
		sum := SHA0([]byte(input))
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("SHA0(%q) = %x, want %s", input, sum, want)
		}
	}
}
