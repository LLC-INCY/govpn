package mschap

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from RFC 3079 section 5.2 ("GetMasterKey" / "GetAsymmetricStartKey").
// These constructions are used almost nowhere else and are easy to get subtly
// wrong, so they are pinned to the RFC's own values.
const (
	rfc3079Password = "clientPass"
	rfc3079Username = "User"
)

var (
	rfc3079AuthChallenge = [ChallengeLen]byte{
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
	}
	rfc3079PeerChallenge = [ChallengeLen]byte{
		0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
		0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E,
	}
)

func TestGetMasterKey_RFC3079(t *testing.T) {
	nt := GenerateNTResponse(rfc3079AuthChallenge, rfc3079PeerChallenge, rfc3079Username, rfc3079Password)
	// RFC 3079 3.5.3 "NT-Response" (identical to RFC 2759 9.2).
	if want := "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df"; hex.EncodeToString(nt[:]) != want {
		t.Fatalf("NTResponse = %s, want %s", hex.EncodeToString(nt[:]), want)
	}

	master := GetMasterKey(rfc3079Password, nt)
	// RFC 3079 3.5.3 "MasterKey".
	if want := "fdece3717a8c838cb388e527ae3cdd31"; hex.EncodeToString(master[:]) != want {
		t.Errorf("GetMasterKey = %s, want %s", hex.EncodeToString(master[:]), want)
	}
}

func TestGetAsymmetricStartKey_RFC3079(t *testing.T) {
	nt := GenerateNTResponse(rfc3079AuthChallenge, rfc3079PeerChallenge, rfc3079Username, rfc3079Password)
	master := GetMasterKey(rfc3079Password, nt)

	// RFC 3079 3.5.3 "SendStartKey128". The RFC derives it from the SERVER's
	// point of view (IsSend=TRUE, IsServer=TRUE), which selects Magic3 — the
	// same string a CLIENT selects for its RECEIVE key. So the client's
	// receive key is the value the RFC prints as the send start key.
	recv := GetAsymmetricStartKey(master, 16, false)
	if want := "8b7cdc149b993a1ba118cb153f56dccb"; hex.EncodeToString(recv) != want {
		t.Errorf("client receive key = %s, want %s", hex.EncodeToString(recv), want)
	}
	// The client's send key uses Magic2 and is necessarily different; assert
	// it is stable and distinct so a magic-string swap cannot go unnoticed.
	send := GetAsymmetricStartKey(master, 16, true)
	if hex.EncodeToString(send) == hex.EncodeToString(recv) {
		t.Error("send and receive keys must differ")
	}
	if want := "d5f0e9521e3ea9589645e86051c82226"; hex.EncodeToString(send) != want {
		t.Errorf("client send key = %s, want %s", hex.EncodeToString(send), want)
	}
}

func TestHLAKLayout(t *testing.T) {
	// The HLAK is send||receive; SSTP binds exactly these 32 bytes.
	hlak := HLAK(rfc3079Username, rfc3079Password, rfc3079AuthChallenge, rfc3079PeerChallenge)
	nt := GenerateNTResponse(rfc3079AuthChallenge, rfc3079PeerChallenge, rfc3079Username, rfc3079Password)
	master := GetMasterKey(rfc3079Password, nt)

	if !bytes.Equal(hlak[:16], GetAsymmetricStartKey(master, 16, true)) {
		t.Error("HLAK[0:16] is not the send key")
	}
	if !bytes.Equal(hlak[16:], GetAsymmetricStartKey(master, 16, false)) {
		t.Error("HLAK[16:32] is not the receive key")
	}
}
