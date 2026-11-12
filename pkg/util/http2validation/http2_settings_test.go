/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package http2validation provides regression tests for the CVE-2026-33814
// fix (GO-2026-4918), which adds Setting.Valid() validation in the HTTP/2
// transport's processSettingsNoWrite before applying received SETTINGS values.
// Without this fix, a malicious server can send SETTINGS_MAX_FRAME_SIZE=0,
// causing the client to enter an infinite loop writing zero-length
// CONTINUATION frames.
//
// TestTransportRejectsZeroMaxFrameSize is the primary regression test: it
// creates a raw TCP server that performs the HTTP/2 handshake and sends
// SETTINGS with MaxFrameSize=0 after the connection is established. The
// patched transport detects the invalid setting via s.Valid() and closes
// the connection with a protocol error, while unpatched code would accept
// MaxFrameSize=0 and hang on subsequent header writes.
package http2validation

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestTransportRejectsZeroMaxFrameSize is a transport-level regression test
// for CVE-2026-33814. It verifies that the HTTP/2 transport rejects a
// SETTINGS frame containing MaxFrameSize=0 rather than applying it (which
// would cause an infinite CONTINUATION write loop on the next request).
func TestTransportRejectsZeroMaxFrameSize(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Set a generous read deadline so the server goroutine exits.
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return
		}

		// Read and discard HTTP/2 client connection preface (24 bytes).
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			return
		}

		fr := http2.NewFramer(conn, conn)

		// Read client SETTINGS frame.
		if _, err := fr.ReadFrame(); err != nil {
			return
		}

		// Send empty (valid) server SETTINGS to complete the handshake.
		if err := fr.WriteSettings(); err != nil {
			return
		}
		// ACK the client's SETTINGS.
		if err := fr.WriteSettingsAck(); err != nil {
			return
		}

		// Wait for the client's SETTINGS ACK.
		if _, err := fr.ReadFrame(); err != nil {
			return
		}

		// Now send the invalid SETTINGS with MaxFrameSize=0.
		// With the fix, processSettingsNoWrite calls s.Valid() which
		// returns ErrCodeProtocol for values < 16384.
		if err := fr.WriteSettings(http2.Setting{
			ID:  http2.SettingMaxFrameSize,
			Val: 0,
		}); err != nil {
			return
		}

		// Drain frames until the client closes the connection.
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()

	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://dummy.tld/", nil)
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}

	// With the fix, the transport detects the invalid SETTINGS_MAX_FRAME_SIZE
	// via s.Valid() and returns a connection error.
	// Without the fix, the transport accepts MaxFrameSize=0, and the next
	// header write enters an infinite CONTINUATION loop (hang).
	if err == nil {
		t.Fatal("RoundTrip succeeded; want error from invalid SETTINGS_MAX_FRAME_SIZE=0")
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("transport hung (context deadline) instead of detecting invalid MaxFrameSize=0; CVE-2026-33814 fix may be missing")
	}
	t.Logf("transport correctly rejected invalid MaxFrameSize=0: %v", err)

	<-serverDone
}

// TestSettingValidRejectsInvalidMaxFrameSize verifies at the type level that
// Setting.Valid() rejects out-of-range MaxFrameSize values per RFC 7540
// §6.5.2 (must be 16384..16777215). This helper-level check pre-existed the
// CVE fix; the transport-level test above is the actual regression test.
func TestSettingValidRejectsInvalidMaxFrameSize(t *testing.T) {
	for _, val := range []uint32{0, 1, 16383, 1 << 24} {
		s := http2.Setting{ID: http2.SettingMaxFrameSize, Val: val}
		if err := s.Valid(); err == nil {
			t.Errorf("Setting{MaxFrameSize, %d}.Valid() = nil; want error", val)
		}
	}
}

// TestSettingValidAcceptsValidMaxFrameSize verifies that valid MaxFrameSize
// values are accepted.
func TestSettingValidAcceptsValidMaxFrameSize(t *testing.T) {
	for _, val := range []uint32{16384, 32768, 1<<24 - 1} {
		s := http2.Setting{ID: http2.SettingMaxFrameSize, Val: val}
		if err := s.Valid(); err != nil {
			t.Errorf("Setting{MaxFrameSize, %d}.Valid() = %v; want nil", val, err)
		}
	}
}
