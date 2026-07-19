package stogashttp

import "sync"

type requestDrain struct {
	mu       sync.Mutex
	active   int
	draining bool
	idle     chan struct{}
}

func newRequestDrain() *requestDrain {
	idle := make(chan struct{})
	close(idle)
	return &requestDrain{idle: idle}
}

func (d *requestDrain) begin() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.draining {
		return false
	}
	if d.active == 0 {
		d.idle = make(chan struct{})
	}
	d.active++
	return true
}

func (d *requestDrain) end() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active == 0 {
		return
	}
	d.active--
	if d.active == 0 {
		close(d.idle)
	}
}

func (d *requestDrain) start() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.draining = true
	return d.idle
}
