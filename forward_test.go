package govpn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestRegisterPortForward(t *testing.T) {
	hostListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostListener.Close()

	hostErr := make(chan error, 1)
	go func() {
		connection, err := hostListener.Accept()
		if err != nil {
			hostErr <- err
			return
		}
		defer connection.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil {
			hostErr <- err
			return
		}
		if string(request) != "ping" {
			hostErr <- io.ErrUnexpectedEOF
			return
		}
		_, err = connection.Write([]byte("pong"))
		hostErr <- err
	}()

	localDevice, remoteDevice := newTestPacketPair()
	session, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.2/24")}, 1500, localDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	remoteSession, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.3/24")}, 1500, remoteDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remoteSession.Close()
	hostPort := hostListener.Addr().(*net.TCPAddr).Port
	forward, err := session.RegisterPortForward(context.Background(), PortForwardSpec{
		Network:       "tcp4",
		ListenAddress: "10.0.0.200:" + strconv.Itoa(hostPort),
		TargetAddress: hostListener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()

	if !containsPrefix(session.Addresses(), netip.MustParsePrefix("10.0.0.200/32")) {
		t.Fatalf("forward address was not registered: %v", session.Addresses())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := remoteSession.DialContext(ctx, "tcp4", "10.0.0.200:"+strconv.Itoa(hostPort))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q", reply)
	}
	if err := <-hostErr; err != nil {
		t.Fatal(err)
	}
	if err := forward.Close(); err != nil {
		t.Fatal(err)
	}
	if containsPrefix(session.Addresses(), netip.MustParsePrefix("10.0.0.200/32")) {
		t.Fatalf("forward address was not removed: %v", session.Addresses())
	}
}

func TestRegisterPortForwardRejectsUnsupportedSpec(t *testing.T) {
	session, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.2/24")}, 1500, testPacketDevice{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, spec := range []PortForwardSpec{
		{Network: "udp4", ListenAddress: "10.0.0.200:8080", TargetAddress: "127.0.0.1:8080"},
		{Network: "tcp4", ListenAddress: "10.0.0.200:8080", TargetAddress: ":8080"},
	} {
		if _, err := session.RegisterPortForward(context.Background(), spec); err == nil {
			t.Fatalf("RegisterPortForward(%+v) succeeded", spec)
		}
	}
}

func TestICMPEcho(t *testing.T) {
	leftDevice, rightDevice := newTestPacketPair()
	left, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.2/24")}, 1500, leftDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.3/24")}, 1500, rightDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()

	conn, err := left.DialICMP4Context(context.Background(), "172.20.0.3")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetTTL(1); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{8, 0, 0, 0, 0, 1, 0, 1}); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, 128)
	n, source, err := conn.ReadFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if source.String() != "172.20.0.3" {
		t.Fatalf("source = %s", source)
	}
	if n < 8 || message[0] != 0 || message[1] != 0 {
		t.Fatalf("unexpected ICMP reply: %x", message[:n])
	}
}

func TestICMPv6Echo(t *testing.T) {
	leftDevice, rightDevice := newTestPacketPair()
	left, err := NewSession([]netip.Prefix{netip.MustParsePrefix("2001:db8::2/64")}, 1500, leftDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := NewSession([]netip.Prefix{netip.MustParsePrefix("2001:db8::3/64")}, 1500, rightDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()

	conn, err := left.DialICMP6Context(context.Background(), "2001:db8::3")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetHopLimit(1); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{128, 0, 0, 0, 0, 1, 0, 1}); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, 128)
	n, source, err := conn.ReadFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if source.String() != "2001:db8::3" {
		t.Fatalf("source = %s", source)
	}
	if n < 8 || message[0] != 129 || message[1] != 0 {
		t.Fatalf("unexpected ICMPv6 reply: %x", message[:n])
	}
}

func TestICMPListenAndWriteTo(t *testing.T) {
	leftDevice, rightDevice := newTestPacketPair()
	left, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.2/24")}, 1500, leftDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.3/24")}, 1500, rightDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()

	listener, err := left.ListenICMP4("")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sender, err := right.DialICMP4("172.20.0.2")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.WriteTo([]byte{8, 0, 0, 0, 0, 2, 0, 1}, &net.IPAddr{IP: net.ParseIP("172.20.0.2")}); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, 128)
	n, source, err := listener.ReadFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if source.String() != "172.20.0.3" || n < 8 || message[0] != 8 || message[1] != 0 {
		t.Fatalf("unexpected request: source=%s packet=%x", source, message[:n])
	}
}

func TestICMPTracerouteTimeExceeded(t *testing.T) {
	leftDevice, rightDevice := newTestPacketPair()
	left, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.2/24")}, 1500, leftDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	listener, err := left.ListenICMP4("")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetTTL(1); err != nil {
		t.Fatal(err)
	}
	quoted := ipv4Packet(netip.MustParseAddr("172.20.0.2"), netip.MustParseAddr("192.0.2.1"), []byte{8, 0, 0, 0, 0, 3, 0, 1})
	errorMessage := append([]byte{11, 0, 0, 0}, quoted[:28]...)
	putChecksum(errorMessage)
	packet := ipv4Packet(netip.MustParseAddr("172.20.0.1"), netip.MustParseAddr("172.20.0.2"), errorMessage)
	if err := rightDevice.Inject(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, 256)
	n, source, err := listener.ReadFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if source.String() != "172.20.0.1" || n < 8 || message[0] != 11 || message[1] != 0 {
		t.Fatalf("unexpected time exceeded: source=%s packet=%x", source, message[:n])
	}
}

func TestICMPv6TracerouteTimeExceeded(t *testing.T) {
	leftDevice, rightDevice := newTestPacketPair()
	left, err := NewSession([]netip.Prefix{netip.MustParsePrefix("2001:db8::2/64")}, 1500, leftDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	listener, err := left.ListenICMP6("")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetHopLimit(1); err != nil {
		t.Fatal(err)
	}
	router := netip.MustParseAddr("2001:db8::1")
	destination := netip.MustParseAddr("2001:db8::2")
	quoted := ipv6Packet(destination, netip.MustParseAddr("2001:db8::9"), []byte{128, 0, 0, 0, 0, 3, 0, 1})
	errorMessage := append([]byte{3, 0, 0, 0}, quoted[:48]...)
	putICMPv6Checksum(router, destination, errorMessage)
	packet := ipv6Packet(router, destination, errorMessage)
	if err := rightDevice.Inject(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, 256)
	n, source, err := listener.ReadFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if source.String() != router.String() || n < 8 || message[0] != 3 || message[1] != 0 {
		t.Fatalf("unexpected ICMPv6 time exceeded: source=%s packet=%x", source, message[:n])
	}
}

func TestICMPMalformedPacketIgnored(t *testing.T) {
	leftDevice, rightDevice := newTestPacketPair()
	left, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.2/24")}, 1500, leftDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	listener, err := left.ListenICMP4("")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	message := []byte{11, 0, 0, 0, 0, 0, 0, 0}
	packet := ipv4Packet(netip.MustParseAddr("172.20.0.1"), netip.MustParseAddr("172.20.0.2"), message)
	packet[len(packet)-1] ^= 0xff
	if err := rightDevice.Inject(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err = listener.ReadFrom(make([]byte, 64))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("malformed packet error = %v, want timeout", err)
	}
}

func TestICMPDeadlineAndClose(t *testing.T) {
	leftDevice, _ := newTestPacketPair()
	left, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.2/24")}, 1500, leftDevice, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	conn, err := left.DialICMP4("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.ReadFrom(make([]byte, 64))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read error = %v, want timeout", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.ReadFrom(make([]byte, 64))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read after close = %v, want EOF", err)
	}
}

func TestICMPDialValidation(t *testing.T) {
	device := testPacketDevice{}
	session, err := NewSession([]netip.Prefix{netip.MustParsePrefix("172.20.0.2/24")}, 1500, device, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.DialICMP("icmp", "192.0.2.1"); err == nil {
		t.Fatal("DialICMP accepted unsupported network")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.DialICMP4Context(ctx, "192.0.2.1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial error = %v", err)
	}
	if _, err := session.DialICMP4(""); err == nil {
		t.Fatal("DialICMP4 accepted an empty destination")
	}
}

func ipv4Packet(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	copy(packet[20:], payload)
	putChecksum(packet[20:])
	putChecksum(packet[:20])
	return packet
}

func ipv6Packet(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	packet[6] = byte(icmpProtocolNumber6)
	packet[7] = 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	copy(packet[40:], payload)
	putICMPv6Checksum(source, destination, packet[40:])
	return packet
}

func putICMPv6Checksum(source, destination netip.Addr, payload []byte) {
	if len(payload) < 4 {
		return
	}
	payload[2], payload[3] = 0, 0
	checksumData := make([]byte, 0, 40+len(payload))
	sourceBytes, destinationBytes := source.As16(), destination.As16()
	checksumData = append(checksumData, sourceBytes[:]...)
	checksumData = append(checksumData, destinationBytes[:]...)
	length := make([]byte, 8)
	binary.BigEndian.PutUint32(length[4:], uint32(len(payload)))
	checksumData = append(checksumData, length...)
	checksumData = append(checksumData, 0, 0, 0, icmpProtocolNumber6)
	checksumData = append(checksumData, payload...)
	checksum := checksumValue(checksumData)
	payload[2] = byte(checksum >> 8)
	payload[3] = byte(checksum)
}

const icmpProtocolNumber6 = 58

func putChecksum(packet []byte) {
	if len(packet) < 4 {
		return
	}
	packet[2], packet[3] = 0, 0
	checksum := checksumValue(packet)
	packet[2] = byte(checksum >> 8)
	packet[3] = byte(checksum)
}

func checksumValue(packet []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(packet); i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	if len(packet)&1 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func containsPrefix(prefixes []netip.Prefix, want netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == want {
			return true
		}
	}
	return false
}

type testPacketDevice struct{}

func (testPacketDevice) Inject(context.Context, []byte) error { return nil }

func (testPacketDevice) Receive(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (testPacketDevice) Close() error { return nil }

type testPacketPairDevice struct {
	inbox  chan []byte
	closed chan struct{}
	once   sync.Once
	peer   *testPacketPairDevice
}

func newTestPacketPair() (*testPacketPairDevice, *testPacketPairDevice) {
	left := &testPacketPairDevice{inbox: make(chan []byte, 128), closed: make(chan struct{})}
	right := &testPacketPairDevice{inbox: make(chan []byte, 128), closed: make(chan struct{})}
	left.peer, right.peer = right, left
	return left, right
}

func (d *testPacketPairDevice) Inject(ctx context.Context, packet []byte) error {
	copyPacket := append([]byte(nil), packet...)
	select {
	case d.peer.inbox <- copyPacket:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-d.closed:
		return net.ErrClosed
	case <-d.peer.closed:
		return net.ErrClosed
	}
}

func (d *testPacketPairDevice) Receive(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-d.inbox:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.closed:
		return nil, net.ErrClosed
	}
}

func (d *testPacketPairDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}
