package controller

import (
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// eventThrottle rate-limits a repeated event per object, so a condition that
// recurs on every requeue is announced once per interval instead of once per
// pass. A requeue loop is driven by controller-runtime's backoff, which starts
// in milliseconds: without a throttle a single wedged request would fill the
// object's event stream (and the apiserver's event budget) with the same note.
//
// The zero value is usable: the map is created on first use, a zero interval
// falls back to defaultEventThrottleInterval, and a nil clock to time.Now.
// Because it carries a mutex, it must only ever be used through a pointer to
// its owner - never copied.
type eventThrottle struct {
	mu   sync.Mutex
	last map[types.UID]time.Time

	// interval is the minimum spacing between two events for the same object.
	interval time.Duration
	// nowFunc is the clock, replaced in tests to advance time without sleeping.
	nowFunc func() time.Time
}

// defaultEventThrottleInterval is the spacing used when an eventThrottle does
// not configure one. It is deliberately coarse: the event exists so an operator
// looking at `kubectl describe` sees the condition at all, not so they can
// count its occurrences, and the reconcile keeps requeueing either way.
const defaultEventThrottleInterval = 5 * time.Minute

// allow reports whether an event may be emitted for uid now, and records the
// emission when it says yes. The first occurrence for an object always passes;
// further occurrences pass once the interval has elapsed.
//
// Entries older than the interval are dropped on every call, so the map holds
// only objects seen within the last window rather than growing with every
// request the controller has ever throttled. Keying on the UID (not the
// namespaced name) gives a recreated request its own budget.
func (t *eventThrottle) allow(uid types.UID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	interval := t.interval
	if interval <= 0 {
		interval = defaultEventThrottleInterval
	}
	now := time.Now()
	if t.nowFunc != nil {
		now = t.nowFunc()
	}

	for key, seen := range t.last {
		if now.Sub(seen) >= interval {
			delete(t.last, key)
		}
	}

	if _, throttled := t.last[uid]; throttled {
		return false
	}
	if t.last == nil {
		t.last = make(map[types.UID]time.Time)
	}
	t.last[uid] = now

	return true
}
