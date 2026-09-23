package proxy

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

func fmtErr(s string) error { return errors.New(s) }

func newBufReader(c net.Conn) *bufio.Reader { return bufio.NewReaderSize(c, 32*1024) }

// connRespWriter 把 http.ResponseWriter 写到 TLS 连接上（MITM 内循环用）。
type connRespWriter struct {
	conn        net.Conn
	req         *http.Request
	header      http.Header
	status      int
	closeAfter  bool
	wroteHeader bool
	reader      *bufio.Reader
}

func (w *connRespWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.wroteHeader {
		return nil, nil, errors.New("response already started")
	}
	w.wroteHeader = true
	reader := w.reader
	if reader == nil {
		reader = bufio.NewReader(w.conn)
	}
	return w.conn, bufio.NewReadWriter(reader, bufio.NewWriter(w.conn)), nil
}

func newRespWriter(conn net.Conn, req *http.Request) *connRespWriter {
	// This writer streams an unknown-length body directly to the TLS socket.
	// End every response by closing the connection so HTTP/1.1 clients can
	// determine where the body ends.
	closeAfter := true
	for _, v := range req.Header.Values("Connection") {
		if strings_EqualFold(v, "close") {
			closeAfter = true
		}
	}
	return &connRespWriter{conn: conn, req: req, header: make(http.Header), closeAfter: closeAfter}
}

func (w *connRespWriter) Header() http.Header { return w.header }

func (w *connRespWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.header.Set("Connection", "close")
	var buf bufio.Writer
	_ = buf
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        w.header,
		Body:          nil,
		ContentLength: -1,
	}
	if w.req.Method == http.MethodHead {
		resp.Body = http.NoBody
	}
	_ = resp.Write(w.conn)
}

func (w *connRespWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(p)
}

func strings_EqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
