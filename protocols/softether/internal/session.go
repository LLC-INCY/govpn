package softether

import "errors"

const (
	AuthAnonymous     uint32 = 0
	AuthPassword      uint32 = 1
	AuthPlainPassword uint32 = 2
	AuthCertificate   uint32 = 3

	ProtocolTCP uint32 = 0
)

type Policy struct {
	Access                          bool
	DHCPFilter                      bool
	DHCPNoServer                    bool
	DHCPForce                       bool
	NoBridge                        bool
	NoRouting                       bool
	PrivacyFilter                   bool
	NoServer                        bool
	CheckMAC                        bool
	CheckIP                         bool
	ARPDHCPOnly                     bool
	MonitorPort                     bool
	NoBroadcastLimiter              bool
	FixPassword                     bool
	NoQoS                           bool
	RSAndRAFilter                   bool
	RAFilter                        bool
	DHCPv6Filter                    bool
	DHCPv6NoServer                  bool
	NoRoutingV6                     bool
	CheckIPv6                       bool
	NoServerV6                      bool
	NoSavePassword                  bool
	FilterIPv4                      bool
	FilterIPv6                      bool
	FilterNonIP                     bool
	NoIPv6DefaultRouterInRA         bool
	NoIPv6DefaultRouterInRAWhenIPv6 bool
	MaxConnection                   uint32
	Timeout                         uint32
	MaxMAC                          uint32
	MaxIP                           uint32
	MaxUpload                       uint32
	MaxDownload                     uint32
	MultiLogins                     uint32
	MaxIPv6                         uint32
	AutoDisconnect                  uint32
	VLANID                          uint32
}

type SessionParameters struct {
	SessionName    string
	ConnectionName string
	MaxConnection  uint32
	UseEncrypt     bool
	UseCompress    bool
	HalfConnection bool
	Timeout        uint32
	QoS            bool
	SessionKey     [20]byte
	SessionKey32   uint32
	VLANID         uint32
	Policy         Policy
}

func ParseSessionParameters(pack *Pack) (SessionParameters, error) {
	var parameters SessionParameters
	parameters.SessionName = pack.GetString("session_name")
	parameters.ConnectionName = pack.GetString("connection_name")
	if parameters.SessionName == "" || parameters.ConnectionName == "" {
		return parameters, errors.New("softether: welcome is missing session or connection name")
	}
	key := pack.GetData("session_key")
	if len(key) != len(parameters.SessionKey) {
		return parameters, errors.New("softether: welcome has invalid session key")
	}
	copy(parameters.SessionKey[:], key)
	parameters.SessionKey32 = pack.GetInt("session_key_32")
	parameters.MaxConnection = pack.GetInt("max_connection")
	if parameters.MaxConnection == 0 {
		parameters.MaxConnection = 1
	}
	if parameters.MaxConnection > 32 {
		parameters.MaxConnection = 32
	}
	parameters.UseEncrypt = pack.GetInt("use_encrypt") != 0
	parameters.UseCompress = pack.GetInt("use_compress") != 0
	parameters.HalfConnection = pack.GetInt("half_connection") != 0
	parameters.Timeout = pack.GetInt("timeout")
	parameters.QoS = pack.GetInt("qos") != 0
	parameters.VLANID = pack.GetInt("vlan_id")
	parameters.Policy = PolicyFromPack(pack)
	if !parameters.Policy.Access {
		return parameters, errors.New("softether: server policy denies network access")
	}
	return parameters, nil
}

func PolicyFromPack(pack *Pack) Policy {
	return Policy{
		Access: boolValue(pack, "Access"), DHCPFilter: boolValue(pack, "DHCPFilter"),
		DHCPNoServer: boolValue(pack, "DHCPNoServer"), DHCPForce: boolValue(pack, "DHCPForce"),
		NoBridge: boolValue(pack, "NoBridge"), NoRouting: boolValue(pack, "NoRouting"),
		PrivacyFilter: boolValue(pack, "PrivacyFilter"), NoServer: boolValue(pack, "NoServer"),
		CheckMAC: boolValue(pack, "CheckMac"), CheckIP: boolValue(pack, "CheckIP"),
		ARPDHCPOnly: boolValue(pack, "ArpDhcpOnly"), MonitorPort: boolValue(pack, "MonitorPort"),
		NoBroadcastLimiter: boolValue(pack, "NoBroadcastLimiter"), FixPassword: boolValue(pack, "FixPassword"),
		NoQoS: boolValue(pack, "NoQoS"), RSAndRAFilter: boolValue(pack, "RSandRAFilter"),
		RAFilter: boolValue(pack, "RAFilter"), DHCPv6Filter: boolValue(pack, "DHCPv6Filter"),
		DHCPv6NoServer: boolValue(pack, "DHCPv6NoServer"), NoRoutingV6: boolValue(pack, "NoRoutingV6"),
		CheckIPv6: boolValue(pack, "CheckIPv6"), NoServerV6: boolValue(pack, "NoServerV6"),
		NoSavePassword: boolValue(pack, "NoSavePassword"), FilterIPv4: boolValue(pack, "FilterIPv4"),
		FilterIPv6: boolValue(pack, "FilterIPv6"), FilterNonIP: boolValue(pack, "FilterNonIP"),
		NoIPv6DefaultRouterInRA:         boolValue(pack, "NoIPv6DefaultRouterInRA"),
		NoIPv6DefaultRouterInRAWhenIPv6: boolValue(pack, "NoIPv6DefaultRouterInRAWhenIPv6"),
		MaxConnection:                   intValue(pack, "MaxConnection"), Timeout: intValue(pack, "TimeOut"),
		MaxMAC: intValue(pack, "MaxMac"), MaxIP: intValue(pack, "MaxIP"),
		MaxUpload: intValue(pack, "MaxUpload"), MaxDownload: intValue(pack, "MaxDownload"),
		MultiLogins: intValue(pack, "MultiLogins"), MaxIPv6: intValue(pack, "MaxIPv6"),
		AutoDisconnect: intValue(pack, "AutoDisconnect"), VLANID: intValue(pack, "VLanId"),
	}
}

func AddPolicy(pack *Pack, policy Policy) {
	bools := map[string]bool{
		"Access": policy.Access, "DHCPFilter": policy.DHCPFilter, "DHCPNoServer": policy.DHCPNoServer,
		"DHCPForce": policy.DHCPForce, "NoBridge": policy.NoBridge, "NoRouting": policy.NoRouting,
		"PrivacyFilter": policy.PrivacyFilter, "NoServer": policy.NoServer, "CheckMac": policy.CheckMAC,
		"CheckIP": policy.CheckIP, "ArpDhcpOnly": policy.ARPDHCPOnly, "MonitorPort": policy.MonitorPort,
		"NoBroadcastLimiter": policy.NoBroadcastLimiter, "FixPassword": policy.FixPassword, "NoQoS": policy.NoQoS,
		"RSandRAFilter": policy.RSAndRAFilter, "RAFilter": policy.RAFilter, "DHCPv6Filter": policy.DHCPv6Filter,
		"DHCPv6NoServer": policy.DHCPv6NoServer, "NoRoutingV6": policy.NoRoutingV6, "CheckIPv6": policy.CheckIPv6,
		"NoServerV6": policy.NoServerV6, "NoSavePassword": policy.NoSavePassword, "FilterIPv4": policy.FilterIPv4,
		"FilterIPv6": policy.FilterIPv6, "FilterNonIP": policy.FilterNonIP,
		"NoIPv6DefaultRouterInRA":         policy.NoIPv6DefaultRouterInRA,
		"NoIPv6DefaultRouterInRAWhenIPv6": policy.NoIPv6DefaultRouterInRAWhenIPv6,
	}
	for name, value := range bools {
		pack.AddBool("policy:"+name, value)
	}
	ints := map[string]uint32{
		"MaxConnection": policy.MaxConnection, "TimeOut": policy.Timeout, "MaxMac": policy.MaxMAC,
		"MaxIP": policy.MaxIP, "MaxUpload": policy.MaxUpload, "MaxDownload": policy.MaxDownload,
		"MultiLogins": policy.MultiLogins, "MaxIPv6": policy.MaxIPv6,
		"AutoDisconnect": policy.AutoDisconnect, "VLanId": policy.VLANID,
	}
	for name, value := range ints {
		pack.AddInt("policy:"+name, value)
	}
	pack.AddBool("policy:Ver3", true)
}

func boolValue(pack *Pack, name string) bool  { return pack.GetInt("policy:"+name) != 0 }
func intValue(pack *Pack, name string) uint32 { return pack.GetInt("policy:" + name) }
