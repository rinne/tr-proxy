package supervisor

import (
	"sync"
	"time"
)

// Event is one entry of the in-memory event log.
type Event struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"` // tunnel, listener, config, auth, admin
	Message string    `json:"message"`
}

const maxEvents = 200

// events is a bounded log of recent events, oldest first.
type events struct {
	mu   sync.Mutex
	seq  uint64
	list []Event
}

func (e *events) Add(kind, message string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	e.list = append(e.list, Event{Seq: e.seq, Time: time.Now(), Kind: kind, Message: message})
	if len(e.list) > maxEvents {
		e.list = e.list[len(e.list)-maxEvents:]
	}
}

func (e *events) Snapshot() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Event{}, e.list...)
}
