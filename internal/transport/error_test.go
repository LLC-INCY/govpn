package transport

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/bclswl0827/govpn/internal/packet"
)

func TestNormalizeError(t *testing.T) {
	for _, err := range []error{nil, io.EOF, net.ErrClosed, packet.ErrClosed, fmt.Errorf("wrapped: %w", net.ErrClosed)} {
		if normalized := NormalizeError(err); normalized != nil {
			t.Errorf("NormalizeError(%v) = %v, want nil", err, normalized)
		}
	}
	want := errors.New("failure")
	if got := NormalizeError(want); got != want {
		t.Errorf("NormalizeError(%v) = %v, want original error", want, got)
	}
}
