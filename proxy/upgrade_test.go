package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"njuconnect/core"
)

func TestForwardMergesCookiesOnceAndStoresResponse(t *testing.T) {
	got := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Cookie")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "new", Path: "/"})
	}))
	defer upstream.Close()
	s, _ := core.NewSession()
	u, _ := url.Parse(upstream.URL)
	s.Jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "old"}})
	g := NewGateway(s, nil, "127.0.0.1:0")
	defer g.Close()
	req, _ := http.NewRequest("GET", upstream.URL, nil)
	req.Header.Set("Cookie", "session=browser; application=keep")
	resp, err := g.forward(req, true)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	header := <-got
	if strings.Count(header, "session=") != 1 || !strings.Contains(header, "session=old") || !strings.Contains(header, "application=keep") {
		t.Fatalf("cookies: %s", header)
	}
	if cookies := s.Jar.Cookies(u); len(cookies) != 1 || cookies[0].Value != "new" {
		t.Fatalf("response cookies: %v", cookies)
	}
}

func TestWebSocketThroughProxy(t *testing.T) {
	ca, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, mitm := range []bool{false, true} {
		t.Run(fmt.Sprintf("mitm=%v", mitm), func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !isWebSocket(r.Header) {
					http.Error(w, "missing upgrade", 400)
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
				rw.Flush()
				// A masked client text frame (hello), followed by an unmasked server frame.
				frame := make([]byte, 11)
				if _, err := io.ReadFull(rw, frame); err != nil {
					return
				}
				if string(frame) != string([]byte{0x81, 0x85, 1, 2, 3, 4, 'h' ^ 1, 'e' ^ 2, 'l' ^ 3, 'l' ^ 4, 'o' ^ 1}) {
					return
				}
				conn.Write(append([]byte{0x81, 5}, []byte("hello")...))
				io.Copy(io.Discard, rw)
			}))
			defer upstream.Close()
			s, _ := core.NewSession()
			transport := upstream.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.ServerName = "example.com"
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
			}
			s.Client.Transport = transport
			defer transport.CloseIdleConnections()
			g := NewGateway(s, ca, "127.0.0.1:0")
			defer g.Close()
			g.plain.Transport = transport
			server := httptest.NewServer(g)
			defer server.Close()
			conn, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(conn)
			target := upstream.URL + "/socket"
			if mitm {
				fmt.Fprint(conn, "CONNECT www.nju.edu.cn:443 HTTP/1.1\r\nHost: www.nju.edu.cn:443\r\n\r\n")
				resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
				if err != nil || resp.StatusCode != 200 {
					t.Fatalf("CONNECT: %v %v", resp, err)
				}
				roots := x509.NewCertPool()
				roots.AddCert(ca.caCert)
				tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "www.nju.edu.cn"})
				if err := tlsConn.Handshake(); err != nil {
					t.Fatal(err)
				}
				conn = tlsConn
				reader = bufio.NewReader(conn)
				target = "/socket"
			}
			fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: www.nju.edu.cn\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", target)
			resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 101 || !isWebSocket(resp.Header) {
				t.Fatalf("upgrade failed: %v", resp)
			}
			conn.Write([]byte{0x81, 0x85, 1, 2, 3, 4, 'h' ^ 1, 'e' ^ 2, 'l' ^ 3, 'l' ^ 4, 'o' ^ 1})
			frame := make([]byte, 7)
			if _, err := io.ReadFull(reader, frame); err != nil {
				t.Fatal(err)
			}
			if string(frame) != string(append([]byte{0x81, 5}, []byte("hello")...)) {
				t.Fatalf("bad reply: %q", frame)
			}
			g.Close()
			if _, err := reader.ReadByte(); err == nil {
				t.Fatal("upgrade remained open after stop")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("stop did not close upgrade")
			}
		})
	}
}
