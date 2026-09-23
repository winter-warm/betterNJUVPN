package proxy

import (
	"io"
	"net/http"
	"strings"
)

func isWebSocket(h http.Header) bool {
	if !strings.EqualFold(h.Get("Upgrade"), "websocket") {
		return false
	}
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func (g *Gateway) handleUpgrade(w http.ResponseWriter, r *http.Request, resp *http.Response) {
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok || !isWebSocket(r.Header) || !isWebSocket(resp.Header) {
		http.Error(w, "invalid upstream upgrade", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unavailable", http.StatusBadGateway)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	defer upstream.Close()
	if !g.trackConn(conn) {
		return
	}
	defer g.untrackConn(conn)
	head := *resp
	head.Body = nil
	head.ContentLength = 0
	if err := head.Write(buffered); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, buffered); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	conn.Close()
	upstream.Close()
	<-done
}
