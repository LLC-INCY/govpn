package govpn_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/bclswl0827/govpn/protocols/sstp"
)

// StartTunnel is the entrypoint an embedder with its own OS TUN device uses:
// it must complete the same handshake as Start, report the assigned address,
// and carry raw IP packets in both directions.
func TestSSTPStartTunnelCarriesRawPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	port := freePort(t, "tcp")
	_, cert, key := testPKI(t)
	server, err := sstp.NewServer(sstp.ServerConfig{
		Cert:       cert,
		Key:        key,
		ListenIP:   "127.0.0.1",
		ListenPort: port,
		Pool:       "10.20.0.0/24",
		Users:      map[string]string{"alice": "correct horse battery staple"},
	}).Start(ctx)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() { _ = server.Close() }()

	tunnel, err := sstp.NewClient(sstp.Config{
		Server:     "127.0.0.1",
		Port:       port,
		Username:   "alice",
		Password:   "correct horse battery staple",
		SkipVerify: true,
	}).StartTunnel(ctx)
	if err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	// The address must come from the server's pool: the caller configures its
	// TUN from this, so a zero value would silently produce a dead tunnel.
	pool := netip.MustParsePrefix("10.20.0.0/24")
	if !tunnel.Address.IsValid() || !pool.Contains(tunnel.Address.Addr()) {
		t.Fatalf("assigned address = %v, want one inside %v", tunnel.Address, pool)
	}
	if tunnel.MTU <= 0 {
		t.Errorf("MTU = %d", tunnel.MTU)
	}

	// An ICMP echo to the server's gateway address proves the data path is
	// live end to end, without depending on the host's networking.
	gateway := tunnel.Address.Masked().Addr().Next()
	echo := icmpEchoRequest(tunnel.Address.Addr(), gateway)
	if err := tunnel.WritePacket(ctx, echo); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	readCtx, readCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readCancel()
	reply, err := tunnel.ReadPacket(readCtx)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if len(reply) < 20 {
		t.Fatalf("reply is %d bytes, too short for an IPv4 packet", len(reply))
	}
	if version := reply[0] >> 4; version != 4 {
		t.Errorf("reply IP version = %d, want 4", version)
	}
	// ICMP is protocol 1; anything else means we read an unrelated packet.
	if reply[9] != 1 {
		t.Errorf("reply protocol = %d, want 1 (ICMP)", reply[9])
	}
}

// Close must be safe to call more than once — a client tearing down a tunnel
// races its own read loop, and both paths call Close.
func TestSSTPTunnelCloseIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	port := freePort(t, "tcp")
	_, cert, key := testPKI(t)
	server, err := sstp.NewServer(sstp.ServerConfig{
		Cert: cert, Key: key,
		ListenIP: "127.0.0.1", ListenPort: port,
		Pool:  "10.20.0.0/24",
		Users: map[string]string{"alice": "pw"},
	}).Start(ctx)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() { _ = server.Close() }()

	tunnel, err := sstp.NewClient(sstp.Config{
		Server: "127.0.0.1", Port: port,
		Username: "alice", Password: "pw", SkipVerify: true,
	}).StartTunnel(ctx)
	if err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	if err := tunnel.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := tunnel.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// icmpEchoRequest builds a minimal IPv4 ICMP echo request.
func icmpEchoRequest(src, dst netip.Addr) []byte {
	payload := []byte{
		8, 0, // type 8 (echo request), code 0
		0, 0, // checksum, filled below
		0, 1, // identifier
		0, 1, // sequence
	}
	putChecksum(payload, 2)

	header := make([]byte, 20)
	header[0] = 0x45 // IPv4, 5-word header
	total := len(header) + len(payload)
	header[2], header[3] = byte(total>>8), byte(total)
	header[8] = 64 // TTL
	header[9] = 1  // ICMP
	copy(header[12:16], src.AsSlice())
	copy(header[16:20], dst.AsSlice())
	putChecksum(header, 10)

	return append(header, payload...)
}

// putChecksum writes the standard internet checksum of b into b[offset:offset+2].
func putChecksum(b []byte, offset int) {
	b[offset], b[offset+1] = 0, 0
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	sum = ^sum & 0xffff
	b[offset], b[offset+1] = byte(sum>>8), byte(sum)
}
