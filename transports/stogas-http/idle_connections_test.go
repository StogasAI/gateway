package stogashttp

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestIdleConnectionReclamationPreservesRecentAndActiveSockets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var idle idleConnections
		pair := func() net.Conn {
			a, b := net.Pipe()
			t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
			return a
		}
		old := pair()
		active := pair()
		idle.observe(old, http.StateIdle)
		idle.observe(active, http.StateIdle)
		idle.observe(active, http.StateActive)
		if idle.reclaim() {
			t.Fatal("recently idle connection evicted")
		}
		time.Sleep(serverIdleTimeout)
		recent := pair()
		idle.observe(recent, http.StateIdle)
		// Duplicate notifications must neither add entries nor refresh recency.
		idle.observe(old, http.StateIdle)
		if !idle.reclaim() || idle.reclaim() {
			t.Fatal("did not reclaim exactly the oldest eligible socket")
		}
		if err := old.SetDeadline(time.Now()); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("evicted socket still open", err)
		}
		if err := active.SetDeadline(time.Now()); err != nil {
			t.Fatal("active socket closed", err)
		}
		idle.observe(old, http.StateClosed)
		idle.observe(recent, http.StateHijacked)
		if idle.oldest.Len() != 0 || len(idle.entries) != 0 || idle.evicted != 1 {
			t.Fatal("stale connection tracking retained")
		}
	})
}

// A synchronous listener lets the test order real socket ownership without
// kernel timing or sleeps; the returned connections are ordinary net.Pipe I/O.
type candidateListener struct {
	candidates chan net.Conn
	done       chan struct{}
	once       sync.Once
}

func (l *candidateListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.candidates:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *candidateListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *candidateListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestPublicListenerReclaimsOnlyOnDemandAndReturnsSlotsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := &candidateListener{candidates: make(chan net.Conn, 4), done: make(chan struct{})}
		defer base.Close()
		listener := &publicListener{Listener: base, slots: make(chan struct{}, 1), idle: new(idleConnections)}
		candidate := func() net.Conn {
			a, b := net.Pipe()
			t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
			base.candidates <- a
			return b
		}
		candidate()
		first, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		// Match the production TLS-over-admission wrapping. Pressure closes the
		// transport, avoiding a blocking TLS close_notify under the state lock.
		secured := &ingressTLSConn{Conn: tls.Server(first, &tls.Config{}), deadline: time.Now().Add(sessionSetupBudget)}
		listener.idle.observe(secured, http.StateIdle)
		failed := candidate()
		accepted := make(chan net.Conn, 1)
		go func() { conn, _ := listener.Accept(); accepted <- conn }()
		synctest.Wait()
		var byte [1]byte
		if _, err := failed.Read(byte[:]); err == nil {
			t.Fatal("full recent pool admitted a candidate")
		}
		if listener.idle.evicted != 0 || listener.idle.rejected != 1 {
			t.Fatal("recent pool was displaced")
		}
		time.Sleep(serverIdleTimeout)
		if listener.idle.evicted != 0 {
			t.Fatal("capacity was reclaimed without new demand")
		}
		candidate()
		second := <-accepted
		if second == nil || listener.idle.evicted != 1 || len(listener.slots) != 1 {
			t.Fatal("idle slot was not transferred")
		}
		_ = secured.Close()
		_ = first.Close()
		if len(listener.slots) != 1 {
			t.Fatal("repeated old close released the replacement's slot")
		}
		_ = second.Close()
		_ = second.Close()
		if len(listener.slots) != 0 {
			t.Fatal("slot leaked")
		}
		_ = listener.Close()
		if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatal("closed listener kept accepting")
		}
	})
}

func TestPublicListenerAcceptsBurstsWhenSlotsAreAvailable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := &candidateListener{candidates: make(chan net.Conn, 1), done: make(chan struct{})}
		defer base.Close()
		listener := &publicListener{Listener: base, slots: make(chan struct{}, 1), idle: new(idleConnections)}
		start := time.Now()
		// A whole pool's worth of arrivals at the same instant must succeed
		// when preceding sockets have closed. No hidden per-second quota.
		for range serverConcurrency {
			a, b := net.Pipe()
			base.candidates <- a
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			_ = b.Close()
		}
		if !time.Now().Equal(start) || len(listener.slots) != 0 || listener.idle.rejected != 0 {
			t.Fatal("available capacity was throttled or retained")
		}
	})
}
