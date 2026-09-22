package gui

import (
	"net"
	"sync/atomic"
)

// trafficCounters measures bytes crossing the local proxy listener. Read is
// client upload; Write is client download. Counts last for the App lifetime.
type trafficCounters struct {
	upload   atomic.Uint64
	download atomic.Uint64
}

type trafficListener struct {
	net.Listener
	counters *trafficCounters
}

func (l trafficListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trafficConn{Conn: conn, counters: l.counters}, nil
}

type trafficConn struct {
	net.Conn
	counters *trafficCounters
}

func (c *trafficConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.counters.upload.Add(uint64(n))
	return n, err
}

func (c *trafficConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.counters.download.Add(uint64(n))
	return n, err
}
