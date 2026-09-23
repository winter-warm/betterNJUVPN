package gui

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"njuconnect/core"
)

type authTestTransport func(*http.Request) (*http.Response, error)

func (f authTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthOperationsRejectConcurrentWork(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	sess, _ := core.NewSession()
	sess.SMSAuthId = "test-auth"
	sess.Client.Transport = authTestTransport(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-release
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":1,"message":"test rejection"}`)), Request: r}, nil
	})
	a := &App{state: StateSMSPending, sess: sess, cfg: &core.Config{Username: "original"}}
	if err := a.SubmitSMS("123456"); err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); a.authMu.Lock(); a.authMu.Unlock() }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("SMS request not started")
	}
	for name, operation := range map[string]func() error{
		"login":  func() error { return a.StartLogin("replacement", "secret", false, false) },
		"sms":    func() error { return a.SubmitSMS("123456") },
		"resend": a.ResendSMS,
		"logout": a.Logout,
	} {
		if err := operation(); err == nil {
			t.Errorf("%s accepted during auth", name)
		}
	}
	if a.cfg.Username != "original" || a.state != StateSubmitting {
		t.Fatal("rejected operation mutated state")
	}
}

func TestLoginRejectsActiveStates(t *testing.T) {
	for _, state := range []State{StateLoggingIn, StateSMSPending, StateSubmitting, StateOnline} {
		a := &App{state: state, cfg: &core.Config{}}
		if err := a.StartLogin("test", "test", false, false); err == nil {
			t.Fatalf("accepted login in %s", state)
		}
		if !a.authMu.TryLock() {
			t.Fatal("auth lock leaked")
		}
		a.authMu.Unlock()
	}
}

func TestCorruptSessionRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	sess, _ := core.NewSession()
	if err := loadLoginSession(sess, path, true); err == nil {
		t.Fatal("automatic login silently discarded corrupt session")
	}
	if err := loadLoginSession(sess, path, false); err != nil {
		t.Fatal(err)
	}
	backups, _ := filepath.Glob(path + ".corrupt-*")
	if len(backups) != 1 {
		t.Fatalf("backups: %v", backups)
	}
	data, err := os.ReadFile(backups[0])
	if err != nil || string(data) != "{" {
		t.Fatal("original data not preserved")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("corrupt session still blocks new login")
	}
}

func TestFailedProxyStartPreservesLoginState(t *testing.T) {
	a := &App{state: StateIdle, cfg: &core.Config{}, tun: newTunManager()}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() { _ = a.ServeAPI(ln, http.NewServeMux()); close(done) }()
	defer func() { ln.Close(); <-done }()
	req, _ := http.NewRequest("POST", "http://"+ln.Addr().String()+"/api/proxy", strings.NewReader(`{"Action":"start"}`))
	req.Header.Set("Origin", "http://"+ln.Addr().String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || a.snapshot()["state"] != string(StateIdle) {
		t.Fatal("failed start changed login state")
	}
}
