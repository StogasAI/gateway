package quote

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

type Attester interface {
	Quote(ctx context.Context, reportData [64]byte) ([]byte, error)
}

type AttesterFunc func(ctx context.Context, reportData [64]byte) ([]byte, error)

func (f AttesterFunc) Quote(ctx context.Context, reportData [64]byte) ([]byte, error) {
	return f(ctx, reportData)
}

type PayloadFunc func(ctx context.Context) (reportdata.Payload, error)

type Snapshot struct {
	Payload       reportdata.Payload
	ReportDataHex string
	Quote         []byte
	GeneratedAt   time.Time
}

type Manager struct {
	attester Attester
	build    PayloadFunc
	interval time.Duration
	now      func() time.Time

	mu       sync.RWMutex
	current  *Snapshot
	lastErr  error
	running  bool
	stopOnce sync.Once
}

func New(attester Attester, build PayloadFunc, interval time.Duration) (*Manager, error) {
	if attester == nil {
		return nil, errors.New("attester is required")
	}
	if build == nil {
		return nil, errors.New("payload builder is required")
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Manager{attester: attester, build: build, interval: interval, now: time.Now}, nil
}

func (m *Manager) Current(ctx context.Context) (*Snapshot, error) {
	m.mu.RLock()
	current := cloneSnapshot(m.current)
	lastErr := m.lastErr
	m.mu.RUnlock()
	if current != nil {
		return current, nil
	}
	if err := m.Refresh(ctx); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		if m.lastErr != nil {
			return nil, m.lastErr
		}
		return nil, lastErr
	}
	return cloneSnapshot(m.current), nil
}

func (m *Manager) Refresh(ctx context.Context) error {
	payload, err := m.build(ctx)
	if err != nil {
		m.recordErr(err)
		return err
	}
	hash, err := reportdata.Hash(payload)
	if err != nil {
		m.recordErr(err)
		return err
	}
	quoteBytes, err := m.attester.Quote(ctx, hash)
	if err != nil {
		m.recordErr(err)
		return err
	}
	hashHex, _ := reportdata.HashHex(payload)
	next := &Snapshot{
		Payload:       payload,
		ReportDataHex: hashHex,
		Quote:         append([]byte(nil), quoteBytes...),
		GeneratedAt:   m.now().UTC(),
	}
	m.mu.Lock()
	m.current = next
	m.lastErr = nil
	m.mu.Unlock()
	return nil
}

func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		_ = m.Refresh(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.Refresh(ctx)
			}
		}
	}()
}

func (m *Manager) LastError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

func (m *Manager) recordErr(err error) {
	m.mu.Lock()
	m.lastErr = err
	m.mu.Unlock()
}

func cloneSnapshot(snapshot *Snapshot) *Snapshot {
	if snapshot == nil {
		return nil
	}
	out := *snapshot
	out.Payload.AcceptedCertSHA256 = append([]string(nil), snapshot.Payload.AcceptedCertSHA256...)
	out.Quote = append([]byte(nil), snapshot.Quote...)
	return &out
}
