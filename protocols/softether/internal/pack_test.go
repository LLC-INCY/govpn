package softether

import (
	"encoding/hex"
	"testing"
)

func TestPackOfficialWireLayout(t *testing.T) {
	pack := NewPack()
	pack.AddString("method", "login")
	encoded, err := pack.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// count=1, name length includes the implicit C NUL but the NUL is not on
	// wire, type=VALUE_STR, value count=1, value length=5, "login".
	want, _ := hex.DecodeString("00000001000000076d6574686f640000000200000001000000056c6f67696e")
	if string(encoded) != string(want) {
		t.Fatalf("encoded = %x, want %x", encoded, want)
	}
	decoded, err := UnmarshalPack(want)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.GetString("method") != "login" {
		t.Fatalf("method = %q", decoded.GetString("method"))
	}
}

func TestPackRejectsTrailingData(t *testing.T) {
	pack := NewPack()
	pack.AddInt("error", 0)
	encoded, _ := pack.MarshalBinary()
	encoded = append(encoded, 1)
	if _, err := UnmarshalPack(encoded); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestPackElementNamesAreCaseInsensitive(t *testing.T) {
	pack := NewPack()
	pack.AddString("hubname", "VPNGATE")
	pack.AddString("HubName", "replaced")

	if len(pack.elements) != 1 {
		t.Fatalf("element count = %d, want 1", len(pack.elements))
	}
	if value := pack.GetString("HUBNAME"); value != "VPNGATE" {
		t.Fatalf("hubname = %q, want VPNGATE", value)
	}
}
