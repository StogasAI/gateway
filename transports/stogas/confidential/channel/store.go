package channel

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

var ErrSessionCapacity = errors.New("encrypted session capacity exhausted")

// SessionReservation charges the listener's aggregate memory budget before
// setup. It covers setup and the retained session, including replay state and
// its store entry. Release must be nonblocking and must not call back into Store.
type SessionReservation func() (release func(), ok bool)

type storedSession struct {
	session  *ServerSession
	release  func()
	lastUsed time.Time
	pins     int // Includes starts that are still authenticating.
	active   int // Authenticated requests only; rejected starts never extend idle time.
	retired  bool
	idle     *list.Element
}

// Store owns this VM's encryption sessions. It has no routing or conversation
// state. The listener supplies admission and calls ExpireIdle from its existing
// maintenance loop; no timer or goroutine is allocated per session.
type Store struct {
	mu       sync.Mutex
	setup    *ServerSetup
	reserve  SessionReservation
	sessions map[[32]byte]*storedSession
	idle     list.List // Oldest completed use first; active requests are absent.
	closed   bool
	stats    SessionDiagnostics
}

type SessionDiagnostics struct {
	Open        int    `json:"open"`
	Retained    int    `json:"retained"`
	Active      int    `json:"activeRequests"`
	Created     uint64 `json:"created"`
	Expired     uint64 `json:"expired"`
	Evicted     uint64 `json:"evicted"`
	Rejected    uint64 `json:"rejected"`
	IdleSeconds uint32 `json:"idleSeconds"`
}

func NewStore(setup *ServerSetup, reserve SessionReservation) (*Store, error) {
	if setup == nil || reserve == nil {
		return nil, errors.New("encrypted sessions require setup and memory admission")
	}
	return &Store{setup: setup, reserve: reserve, sessions: make(map[[32]byte]*storedSession), stats: SessionDiagnostics{IdleSeconds: setup.idleSeconds}}, nil
}

// Open installs a session before returning its handshake bytes. The listener
// must Remove it if writing those bytes fails. A closed store never reopens.
func (s *Store) Open(ctx context.Context, hello []byte) ([32]byte, []byte, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return [32]byte{}, nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return [32]byte{}, nil, err
	}
	release, ok := s.reserve()
	if !ok || release == nil {
		s.mu.Lock()
		s.stats.Rejected++
		s.mu.Unlock()
		return [32]byte{}, nil, ErrSessionCapacity
	}
	keep := false
	defer func() {
		if !keep {
			release()
		}
	}()
	session, response, err := s.setup.Accept(ctx, hello)
	if err != nil {
		return [32]byte{}, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = ctx.Err(); err == nil && (s.closed || s.sessions[session.ID()] != nil) {
		err = ErrClosed
	}
	if err != nil {
		session.Close()
		return [32]byte{}, nil, err
	}
	entry := &storedSession{session: session, release: release, lastUsed: time.Now()}
	entry.idle = s.idle.PushBack(entry)
	s.sessions[session.ID()] = entry
	s.stats.Open++
	s.stats.Retained++
	s.stats.Created++
	keep = true
	return session.ID(), response, nil
}

// AcceptStart pins the session while authenticating, without holding the store
// mutex during cryptographic work. The returned request owns that pin until
// Close, even if the session is removed in the meantime.
func (s *Store) AcceptStart(id [32]byte, number uint64, encoded []byte) (*ServerRequest, []byte, error) {
	s.mu.Lock()
	entry := s.sessions[id]
	if entry != nil && s.expired(entry, time.Now()) {
		s.stats.Expired++
		s.retire(id, entry)
		s.mu.Unlock()
		s.finishRetirement(entry)
		return nil, nil, ErrClosed
	}
	if entry == nil {
		s.mu.Unlock()
		return nil, nil, ErrClosed
	}
	entry.pins++
	s.mu.Unlock()

	request, metadata, err := entry.session.AcceptStart(number, encoded)
	s.mu.Lock()
	if err == nil && entry.retired {
		clear(metadata)
		request.Close()
		err = ErrClosed
	}
	if err != nil {
		retire := errors.Is(err, ErrClosed) && !entry.retired
		if retire {
			s.retire(id, entry)
		}
		s.unpin(entry)
		s.mu.Unlock()
		if retire {
			s.finishRetirement(entry)
		}
		return nil, nil, err
	}
	defer s.mu.Unlock()
	entry.active++
	if entry.idle != nil {
		s.idle.Remove(entry.idle)
		entry.idle = nil
	}
	s.stats.Active++
	request.release = func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		entry.active--
		s.stats.Active--
		entry.lastUsed = time.Now()
		if entry.active == 0 && !entry.retired {
			entry.idle = s.idle.PushBack(entry)
		}
		s.unpin(entry)
	}
	return request, metadata, nil
}

// Remove is for failed handshake delivery or an authenticated session-close
// operation. A routing header or unauthenticated request must never call it.
// Admitted requests keep their own ciphers and may finish after removal.
func (s *Store) Remove(id [32]byte) {
	s.mu.Lock()
	entry := s.sessions[id]
	if entry != nil {
		s.retire(id, entry)
	}
	s.mu.Unlock()
	if entry != nil {
		s.finishRetirement(entry)
	}
}

func (s *Store) ExpireIdle() {
	s.mu.Lock()
	var retired, retained []*storedSession
	now := time.Now()
	for id, entry := range s.sessions {
		if s.expired(entry, now) {
			s.stats.Expired++
			s.retire(id, entry)
			retired = append(retired, entry)
		} else {
			entry.pins++
			retained = append(retained, entry)
		}
	}
	s.mu.Unlock()
	for _, entry := range retired {
		s.finishRetirement(entry)
	}
	for _, entry := range retained {
		entry.session.expire(now)
		s.mu.Lock()
		s.unpin(entry)
		s.mu.Unlock()
	}
}

// ReclaimIdle releases the oldest unused sessions under memory pressure. The
// one-minute grace preserves recent reuse and the delayed-start window. Pins
// protect starts that are authenticating, as well as admitted exchanges. A
// forged start never changes recency. The caller enforces shared byte admission.
func (s *Store) ReclaimIdle(maximum int) int {
	if maximum <= 0 || !s.mu.TryLock() {
		return 0
	}
	now := time.Now()
	grace := min(time.Minute, time.Duration(s.setup.idleSeconds)*time.Second)
	var retired []*storedSession
	for item := s.idle.Front(); item != nil && len(retired) < maximum; {
		entry := item.Value.(*storedSession)
		item = item.Next()
		if now.Sub(entry.lastUsed) < grace {
			break
		}
		if entry.pins != 0 {
			continue
		}
		if s.expired(entry, now) {
			s.stats.Expired++
		} else {
			s.stats.Evicted++
		}
		s.retire(entry.session.ID(), entry)
		retired = append(retired, entry)
	}
	s.mu.Unlock()
	for _, entry := range retired {
		s.finishRetirement(entry)
	}
	return len(retired)
}

func (s *Store) Close() {
	s.mu.Lock()
	s.closed = true
	var retired []*storedSession
	for id, entry := range s.sessions {
		s.retire(id, entry)
		retired = append(retired, entry)
	}
	s.mu.Unlock()
	for _, entry := range retired {
		s.finishRetirement(entry)
	}
}

func (s *Store) Diagnostics() SessionDiagnostics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Index helpers run under mu. A retired entry remains charged until cleanup
// and its last authentication attempt or admitted request have finished.
func (s *Store) expired(entry *storedSession, now time.Time) bool {
	return entry.active == 0 && now.Sub(entry.lastUsed) >= time.Duration(s.setup.idleSeconds)*time.Second
}

func (s *Store) retire(id [32]byte, entry *storedSession) {
	delete(s.sessions, id)
	if entry.idle != nil {
		s.idle.Remove(entry.idle)
		entry.idle = nil
	}
	s.stats.Open--
	entry.retired = true
	// Cleanup owns a pin until the core has actually erased its session state.
	entry.pins++
}

// Never wait for a session's cryptographic lock while holding the store index.
// An expensive invalid start must not stall admission for unrelated sessions.
func (s *Store) finishRetirement(entry *storedSession) {
	entry.session.Close()
	s.mu.Lock()
	s.unpin(entry)
	s.mu.Unlock()
}

func (s *Store) unpin(entry *storedSession) {
	entry.pins--
	if entry.retired && entry.pins == 0 {
		s.stats.Retained--
		entry.release()
	}
}
