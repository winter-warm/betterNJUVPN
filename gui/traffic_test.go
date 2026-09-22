package gui

import (
	"io"
	"net"
	"testing"
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
