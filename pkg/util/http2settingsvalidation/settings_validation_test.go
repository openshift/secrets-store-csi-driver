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

// Package http2settingsvalidation contains regression tests for CVE-2026-33814
// (GO-2026-4918). These tests exercise the vendored golang.org/x/net/http2
// transport's SETTINGS_MAX_FRAME_SIZE validation at the protocol level.
//
// CARRY-PATCH CAVEAT: The fix is a source-only backport applied to the
// vendored golang.org/x/net/http2 (v0.38.0). Running `go mod vendor` will
// overwrite the patched vendor/golang.org/x/net/http2/transport.go with the
// unpatched upstream source, silently re-introducing CVE-2026-33814. This
// test catches that regression: it will fail (timeout or hang) if the patch
// is lost during vendor regeneration.
//
// The fix will be superseded when golang.org/x/net is updated to >= v0.53.0,
// which contains the upstream fix natively. At that point, this test remains
// valid as ongoing regression coverage.
package http2settingsvalidation

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// fakeH2Server listens on TCP, completes the HTTP/2 handshake with each
// accepted client, and sends a SETTINGS frame with the configured
// MAX_FRAME_SIZE value. It uses bounded I/O to prevent test hangs.
type fakeH2Server struct {
	t               *testing.T
	ln              net.Listener
	maxFrameSizeVal uint32
	accepted        chan net.Conn // sends accepted conn for cleanup
}

func newFakeH2Server(t *testing.T, maxFrameSize uint32) *fakeH2Server {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &fakeH2Server{
		t:               t,
		ln:              ln,
		maxFrameSizeVal: maxFrameSize,
		accepted:        make(chan net.Conn, 1),
	}
}

func (s *fakeH2Server) addr() string { return s.ln.Addr().String() }

// serve accepts one connection, performs the HTTP/2 handshake, sends
// the test SETTINGS, and drains frames to avoid back-pressure.
func (s *fakeH2Server) serve() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	s.accepted <- conn

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}

	fr := http2.NewFramer(conn, conn)

	// Read client connection preface (24 bytes).
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}

	// Read client's initial SETTINGS frame.
	if _, err := fr.ReadFrame(); err != nil {
		return
	}

	// Read the WINDOW_UPDATE that the client sends after SETTINGS.
	if _, err := fr.ReadFrame(); err != nil {
		return
	}

	// Send valid server SETTINGS.
	if err := fr.WriteSettings(http2.Setting{
		ID:  http2.SettingMaxFrameSize,
		Val: 16384,
	}); err != nil {
		return
	}

	// ACK client's SETTINGS.
	if err := fr.WriteSettingsAck(); err != nil {
		return
	}

	// Read the client's SETTINGS_ACK for our initial SETTINGS.
	if _, err := fr.ReadFrame(); err != nil {
		return
	}

	// Now send the test SETTINGS with the specified MAX_FRAME_SIZE.
	if err := fr.WriteSettings(http2.Setting{
		ID:  http2.SettingMaxFrameSize,
		Val: s.maxFrameSizeVal,
	}); err != nil {
		return
	}

	// Drain frames to avoid blocking the client writer (GOAWAY, ACK, etc).
	for i := 0; i < 20; i++ {
		if _, err := fr.ReadFrame(); err != nil {
			return
		}
	}
}

func (s *fakeH2Server) close() {
	s.ln.Close()
	select {
	case c := <-s.accepted:
		c.Close()
	default:
	}
}

// TestTransportRejectsInvalidMaxFrameSize is a transport-level regression test
// for CVE-2026-33814. It creates a real HTTP/2 client connection via
// http2.Transport.NewClientConn over TCP, feeds it a SETTINGS frame with an
// invalid SETTINGS_MAX_FRAME_SIZE value from a fake server peer, and verifies
// that the client closes the connection (setting Closed=true in the
// connection state) rather than accepting the invalid value.
//
// Without the carry patch (s.Valid() check in processSettingsNoWrite), the
// client accepts MAX_FRAME_SIZE=0, leaves the connection open, and a
// subsequent write would loop forever. With the fix, the client recognizes
// the protocol error and closes the connection promptly.
//
// This test is bounded by per-connection deadlines; a hang indicates the
// vulnerability is present (carry patch lost during vendor regeneration).
func TestTransportRejectsInvalidMaxFrameSize(t *testing.T) {
	tests := []struct {
		name       string
		val        uint32
		wantClosed bool // true = expect connection closed (invalid setting)
	}{
		{
			name:       "zero_causes_connection_close_CVE-2026-33814",
			val:        0,
			wantClosed: true,
		},
		{
			name:       "below_minimum_16383_causes_connection_close",
			val:        16383,
			wantClosed: true,
		},
		{
			name:       "above_maximum_causes_connection_close",
			val:        1 << 24,
			wantClosed: true,
		},
		{
			name:       "valid_minimum_16384_keeps_connection_open",
			val:        16384,
			wantClosed: false,
		},
		{
			name:       "valid_maximum_keeps_connection_open",
			val:        1<<24 - 1,
			wantClosed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeH2Server(t, tt.val)
			defer srv.close()

			serverDone := make(chan struct{}, 1)
			go func() {
				defer func() { serverDone <- struct{}{} }()
				srv.serve()
			}()

			// Dial TCP to the fake server.
			rawConn, err := net.DialTimeout("tcp", srv.addr(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer rawConn.Close()

			// Create HTTP/2 client connection over the raw TCP conn.
			tr := &http2.Transport{
				AllowHTTP: true,
				DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
					return rawConn, nil
				},
			}
			cc, err := tr.NewClientConn(rawConn)
			if err != nil {
				t.Logf("NewClientConn error: %v", err)
				<-serverDone
				if tt.wantClosed {
					return
				}
				t.Fatalf("unexpected NewClientConn error: %v", err)
			}

			// Observe the connection state over a 1-second window.
			//
			// With the fix: invalid settings → readLoop returns
			// ConnectionError → writes GOAWAY → cleanup closes the
			// connection; Closed becomes true within milliseconds.
			//
			// Without the fix: readLoop accepts the invalid value
			// and continues normally; Closed remains false.
			var closed bool
			for i := 0; i < 20; i++ {
				time.Sleep(50 * time.Millisecond)
				closed = cc.State().Closed
				if closed {
					break
				}
			}

			if closed != tt.wantClosed {
				if tt.wantClosed {
					t.Errorf("connection NOT closed after invalid SETTINGS_MAX_FRAME_SIZE=%d "+
						"— carry patch for CVE-2026-33814 may be missing from "+
						"vendor/golang.org/x/net/http2/transport.go", tt.val)
				} else {
					t.Errorf("connection unexpectedly closed for valid SETTINGS_MAX_FRAME_SIZE=%d", tt.val)
				}
			} else {
				t.Logf("SETTINGS_MAX_FRAME_SIZE=%d: Closed=%v (expected)", tt.val, closed)
			}

			<-serverDone
		})
	}
}
