package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCloseTerminatesActiveConnect(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(io.Discard, conn)
		}
	}()
	g := NewGateway(nil, nil, "127.0.0.1:0")
	server := httptest.NewServer(g)
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Addr(), upstream.Addr())
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	g.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = reader.ReadByte()
	if err == nil {
		t.Fatal("CONNECT remained open after pause")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("CONNECT did not close after pause")
	}
}

func TestExternalHTTPSIsBlindTunnel(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("external-ok"))
	}))
	defer upstream.Close()
	g := NewGateway(nil, nil, "127.0.0.1:0")
	proxyServer := httptest.NewServer(g)
	defer proxyServer.Close()
	defer g.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
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
		t.Fatalf("got %q, %v", data, err)
	}
}

func TestPACRoutesOnlyCampusHosts(t *testing.T) {
	g := &Gateway{listen: "127.0.0.1:17999"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17999/proxy.pac", nil)
	g.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PAC status: %d", w.Code)
	}
	for _, want := range []string{"PROXY 127.0.0.1:17999", "dnsDomainIs(host, \".nju.edu.cn\")", "return \"DIRECT\""} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("PAC missing %q", want)
		}
	}
}

func TestGatewayScriptRedirectPreservesNonRedirectBody(t *testing.T) {
	u, _ := url.Parse("https://xk-nju-edu-cn-s.atrust.nju.edu.cn/")
	request := &http.Request{URL: u}
	for _, tc := range []struct {
		body string
		want string
	}{
		{"<script>var locationUrl = \"https://vpn.nju.edu.cn/controller/v1/public/verify?t=abc\";</script>", "https://vpn.nju.edu.cn/controller/v1/public/verify?t=abc"},
		{"<html><title>校园服务</title></html>", ""},
		{"<script>var locationUrl = \"https://other.example/path\";</script>", ""},
	} {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body)), Request: request}
		got, err := gatewayNext(resp)
		if err != nil || got != tc.want {
			t.Fatalf("gatewayNext() = %q, %v; want %q", got, err, tc.want)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil || string(data) != tc.body {
			t.Fatalf("body changed: %q, %v", data, err)
		}
		resp.Body.Close()
	}
}
