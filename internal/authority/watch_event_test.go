package authority

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/fsnotify/fsnotify"
)

// A filesystem event for the watched directory reloads the CA and, when the
// material changed, notifies consumers. Driven by a synthetic event under fake
// time, so the fsnotify branch of watchLoop is exercised without depending on
// the kernel delivering a real event in time.
func TestWatchEventReloadsAndNotifies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		writeCA(t, dir, "ca-1.example.org", 24*time.Hour)
		ca, err := New(dir+"/tls.crt", dir+"/tls.key")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		w := runWatchLoop(t, ca)
		defer w.stop()

		rotated := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
		w.events <- fsnotify.Event{Name: dir + "/tls.crt", Op: fsnotify.Write}
		// Let the drain window elapse so the burst settles and the reload runs.
		time.Sleep(ca.drainWindow + time.Millisecond)
		synctest.Wait()

		select {
		case <-w.notify:
		default:
			t.Fatal("a write event over changed material must notify consumers")
		}
		if bundle := parseChain(t, ca.TrustBundlePEM()); !bundle[0].Equal(rotated.Cert) {
			t.Error("current CA must be the rotated certificate after the event-driven reload")
		}
	})
}

// A burst of events from one atomic rotation is coalesced into a single
// reload, and so a single notification.
func TestWatchEventBurstCoalesces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		writeCA(t, dir, "ca-1.example.org", 24*time.Hour)
		ca, err := New(dir+"/tls.crt", dir+"/tls.key")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		w := runWatchLoop(t, ca)
		defer w.stop()

		writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
		for _, op := range []fsnotify.Op{fsnotify.Create, fsnotify.Write, fsnotify.Rename, fsnotify.Remove} {
			w.events <- fsnotify.Event{Name: dir + "/tls.crt", Op: op}
		}
		time.Sleep(ca.drainWindow + time.Millisecond)
		synctest.Wait()

		notifications := 0
		for {
			select {
			case <-w.notify:
				notifications++
				continue
			default:
			}
			break
		}
		if notifications != 1 {
			t.Errorf("got %d notifications for one coalesced burst, want 1", notifications)
		}
	})
}

// An event that does not touch the material (a chmod) is ignored: no reload,
// no notification.
func TestWatchEventIgnoresChmod(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		writeCA(t, dir, "ca-1.example.org", 24*time.Hour)
		ca, err := New(dir+"/tls.crt", dir+"/tls.key")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		w := runWatchLoop(t, ca)
		defer w.stop()

		writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
		w.events <- fsnotify.Event{Name: dir + "/tls.crt", Op: fsnotify.Chmod}
		time.Sleep(ca.drainWindow + time.Millisecond)
		synctest.Wait()

		select {
		case <-w.notify:
			t.Fatal("a chmod event must not trigger a reload")
		default:
		}
	})
}
