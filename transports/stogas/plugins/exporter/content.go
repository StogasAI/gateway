package exporter

import (
	"encoding/json"
	"time"
)

// Input copies the processed request before its pooled storage is released.
// The transport has already removed policy and encryption credentials.
func (c *Capture) Input(body map[string]json.RawMessage) {
	if c == nil || c.reservation == nil {
		return
	}
	defer c.recordCapture(time.Now())
	size := 2
	for key, value := range body {
		size += len(key)*6 + len(value) + 4
	}
	if !c.grow(size) {
		return
	}
	c.request = make([]byte, 0, size)
	c.request = append(c.request, '{')
	for key, value := range body {
		if len(c.request) > 1 {
			c.request = append(c.request, ',')
		}
		name, _ := json.Marshal(key)
		c.request = append(c.request, name...)
		c.request = append(c.request, ':')
		c.request = append(c.request, value...)
	}
	c.request = append(c.request, '}')
}

// Response and Event copy public JSON before response buffers are reused.
func (c *Capture) Response(body []byte) {
	if c == nil || c.reservation == nil {
		return
	}
	defer c.recordCapture(time.Now())
	if !c.grow(len(body)) {
		return
	}
	clear(c.response)
	c.response = make([]byte, len(body))
	copy(c.response, body)
}
func (c *Capture) Event(body []byte) {
	if c == nil || c.reservation == nil {
		return
	}
	defer c.recordCapture(time.Now())
	capacity := cap(c.events)
	next := capacity
	if len(c.events) == capacity {
		next = max(1, capacity*2)
	}
	if !c.grow(len(body) + (next-capacity)*24) {
		return
	}
	if next != capacity {
		events := make([][]byte, len(c.events), next)
		copy(events, c.events)
		c.events = events
	}
	owned := make([]byte, len(body))
	copy(owned, body)
	c.events = append(c.events, owned)
}

// Metadata retains the exact signed object independently of response framing.
func (c *Capture) Metadata(body []byte) {
	if !c.grow(len(body)) {
		return
	}
	clear(c.metadata)
	c.metadata = append([]byte(nil), body...)
}
