package softether

import "testing"

func TestSessionParametersOfficialFields(t *testing.T) {
	pack := NewPack()
	pack.AddString("session_name", "SID-TEST")
	pack.AddString("connection_name", "CID-TEST")
	pack.AddInt("max_connection", 4)
	pack.AddBool("use_encrypt", true)
	pack.AddBool("use_compress", true)
	pack.AddInt("timeout", 60000)
	pack.AddData("session_key", make([]byte, 20))
	pack.AddInt("session_key_32", 42)
	AddPolicy(pack, Policy{Access: true, MaxConnection: 4, Timeout: 60})

	parameters, err := ParseSessionParameters(pack)
	if err != nil {
		t.Fatal(err)
	}
	if parameters.SessionName != "SID-TEST" || parameters.ConnectionName != "CID-TEST" ||
		parameters.MaxConnection != 4 || !parameters.UseEncrypt || !parameters.UseCompress ||
		!parameters.Policy.Access || parameters.Policy.MaxConnection != 4 {
		t.Fatalf("parameters = %+v", parameters)
	}
}

func TestSessionParametersRejectMissingSessionKey(t *testing.T) {
	pack := NewPack()
	pack.AddString("session_name", "SID-TEST")
	pack.AddString("connection_name", "CID-TEST")
	AddPolicy(pack, Policy{Access: true})
	if _, err := ParseSessionParameters(pack); err == nil {
		t.Fatal("welcome without session key was accepted")
	}
}
