package controller

import (
	"testing"
	"testing/synctest"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// The first event for an object always passes, a repeat inside the interval
// is suppressed, and objects do not share a budget: a wedged request must not
// silence the event for another one.
func TestEventThrottleAllowsOncePerObjectPerInterval(t *testing.T) {
	var throttle eventThrottle // zero value, default interval

	if !throttle.allow("a") {
		t.Fatal("the first event for an object must pass")
	}
	if throttle.allow("a") {
		t.Error("a repeat inside the interval must be suppressed")
	}
	if !throttle.allow("b") {
		t.Error("a different object must have its own budget")
	}
}

// Once the interval has elapsed the object is announced again, and the entry
// that expired is dropped rather than kept forever. Fake time, like the
// sibling throttle tests in events_test.go.
func TestEventThrottleResetsAfterInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var throttle eventThrottle
		uid := types.UID("pcr-uid")

		if !throttle.allow(uid) {
			t.Fatal("the first event must pass")
		}
		time.Sleep(eventThrottleInterval)
		synctest.Wait()
		if !throttle.allow(uid) {
			t.Error("an event after the interval elapsed must pass again")
		}

		// The expired entry for a second object is pruned on the next call, so
		// the map holds only objects seen within the current window.
		throttle.allow("other")
		time.Sleep(eventThrottleInterval)
		synctest.Wait()
		throttle.allow(uid)
		if _, kept := throttle.last["other"]; kept {
			t.Error("an entry older than the interval must be pruned")
		}
	})
}
