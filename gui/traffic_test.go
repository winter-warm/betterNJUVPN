package gui

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"njuconnect/proxy"
)

func TestTrafficConnCountsClientDirections(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	counts := new(trafficCounters)
	proxy := &trafficConn{Conn: server, counters: counts}
	writeDone := make(chan error, 1)
	go func() { _, err := client.Write([]byte("request")); writeDone <- err }()
	buf := make([]byte, 7)
	if _, err := io.ReadFull(proxy, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := io.ReadFull(client, buf[:6]); writeDone <- err }()
	if _, err := proxy.Write([]byte("reply!")); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if got := counts.upload.Load(); got != 7 {
		t.Fatalf("upload = %d", got)
	}
	if got := counts.download.Load(); got != 6 {
		t.Fatalf("download = %d", got)
	}
}

func TestLocalProxyAcceptsExternalHTTPS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("external-ok"))
	}))
	defer upstream.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counts := new(trafficCounters)
	gateway := proxy.NewGateway(nil, nil, listener.Addr().String())
	server := &http.Server{Handler: gateway}
	go func() { _ = server.Serve(trafficListener{Listener: listener, counters: counts}) }()
	defer server.Close()
	defer gateway.Close()
	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	client := upstream.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	client.Transport = transport
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || string(data) != "external-ok" {
		t.Fatalf("external response = %q, %v", data, err)
	}
	if counts.upload.Load() == 0 || counts.download.Load() == 0 {
		t.Fatal("listener did not count proxied traffic")
	}
}
