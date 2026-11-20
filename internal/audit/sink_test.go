package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
)

// lockedBuffer is a bytes.Buffer that a test reads while the sink writes it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// blockingWriter blocks its first Write until release is closed. It records
// every line it was given.
type blockingWriter struct {
	release chan struct{}
	mu      sync.Mutex
	calls   int
	lines   []string
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{release: make(chan struct{})}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.calls++
	first := w.calls == 1
	w.mu.Unlock()
	if first {
		<-w.release
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, string(p))
	return len(p), nil
}

func (w *blockingWriter) written() (calls int, names []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, line := range w.lines {
		names = append(names, recordName(line))
	}
	return w.calls, names
}

// recordName returns request.name of an encoded record line, or the line
// itself when it does not decode.
func recordName(line string) string {
	var rec Record
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return line
	}
	return rec.Request.Name
}

// logLines collects the lines of a funcr logger.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func newTestLogger() (logr.Logger, *logLines) {
	l := &logLines{}
	logger := funcr.New(func(prefix, args string) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.lines = append(l.lines, args)
	}, funcr.Options{})
	return logger, l
}

func (l *logLines) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// testRecord returns a denied record for the request named name.
func testRecord(b *Builder, name string) Record {
	pcr := testPCR()
	pcr.Name = name
	return b.Terminal(EventDenied, string(outcome.InvalidUserConfig), "denied", pcr, nil, nil)
}

// recordAsync calls s.Record in a new goroutine and returns a channel that is
// closed when Record returns.
func recordAsync(ctx context.Context, s *WriterSink, rec Record) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Record(ctx, rec)
	}()
	return done
}

// timedRecord calls s.Record and returns how much fake time it took.
func timedRecord(ctx context.Context, s *WriterSink, rec Record) time.Duration {
	start := time.Now()
	s.Record(ctx, rec)
	return time.Since(start)
}

func TestSinkWritesInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newTestBuilder(t, DefaultOptions())
		var buf lockedBuffer
		logger, logs := newTestLogger()
		s := NewWriterSink(&buf, b, logger, DefaultWriteTimeout)
		defer s.Close()

		var wg sync.WaitGroup
		for i := range 100 {
			wg.Go(func() { s.Record(t.Context(), testRecord(b, fmt.Sprintf("pcr-%03d", i))) })
		}
		wg.Wait()

		out := buf.String()
		if !strings.HasSuffix(out, "\n") {
			t.Fatalf("output does not end in a newline: %q", out)
		}
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if len(lines) != 100 {
			t.Fatalf("got %d lines, want 100", len(lines))
		}
		seen := make(map[string]bool)
		for _, line := range lines {
			var rec Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("line %q is not valid JSON: %v", line, err)
			}
			seen[rec.Request.Name] = true
		}
		if len(seen) != 100 {
			t.Errorf("got %d distinct records, want 100", len(seen))
		}
		if got := logs.get(); len(got) != 0 {
			t.Errorf("logged %q, want nothing", got)
		}
	})
}

func TestSinkStalledWriter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newTestBuilder(t, DefaultOptions())
		w := newBlockingWriter()
		logger, logs := newTestLogger()
		s := NewWriterSink(w, b, logger, DefaultWriteTimeout)
		defer s.Close()

		if d := timedRecord(t.Context(), s, testRecord(b, "first")); d != DefaultWriteTimeout {
			t.Errorf("first Record took %v, want the write timeout %v", d, DefaultWriteTimeout)
		}
		for _, name := range []string{"dropped-1", "dropped-2"} {
			if d := timedRecord(t.Context(), s, testRecord(b, name)); d != 0 {
				t.Errorf("Record %s on a stalled sink took %v, want 0", name, d)
			}
		}
		if got := logs.get(); len(got) != 0 {
			t.Errorf("logged %q while the write is blocked, want nothing", got)
		}

		close(w.release)
		synctest.Wait()

		got := logs.get()
		if len(got) != 1 || !strings.Contains(got[0], `"dropped"=2`) {
			t.Errorf("logged %q, want one line that reports 2 dropped records", got)
		}
		if d := timedRecord(t.Context(), s, testRecord(b, "after")); d != 0 {
			t.Errorf("Record after the release took %v, want 0", d)
		}
		synctest.Wait()
		calls, names := w.written()
		if want := []string{"first", "after"}; calls != 2 || strings.Join(names, ",") != strings.Join(want, ",") {
			t.Errorf("writer got %d calls with records %v, want 2 calls with %v", calls, names, want)
		}
		if got := logs.get(); len(got) != 1 {
			t.Errorf("logged %q, want only the line about the dropped records", got)
		}
	})
}

func TestSinkStallsWhileWaitingForHandOver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newTestBuilder(t, DefaultOptions())
		w := newBlockingWriter()
		logger, logs := newTestLogger()
		s := NewWriterSink(w, b, logger, DefaultWriteTimeout)
		defer s.Close()
		// The caller of this record gives up after the hand-over, so it does
		// not mark the sink stalled. Its write stays blocked.
		ctx, cancel := context.WithCancel(t.Context())
		handedOver := recordAsync(ctx, s, testRecord(b, "handed-over"))
		synctest.Wait()
		cancel()
		<-handedOver

		if d := timedRecord(t.Context(), s, testRecord(b, "waited")); d != DefaultWriteTimeout {
			t.Errorf("Record waiting for the hand-over took %v, want the write timeout %v", d, DefaultWriteTimeout)
		}
		if d := timedRecord(t.Context(), s, testRecord(b, "stalled")); d != 0 {
			t.Errorf("Record on a stalled sink took %v, want 0", d)
		}

		close(w.release)
		synctest.Wait()
		if got := logs.get(); len(got) != 1 || !strings.Contains(got[0], `"dropped"=2`) {
			t.Errorf("logged %q, want one line that reports 2 dropped records", got)
		}
		if calls, names := w.written(); calls != 1 || names[0] != "handed-over" {
			t.Errorf("writer got %d calls with records %v, want only handed-over", calls, names)
		}
	})
}

func TestSinkRecordReturnsOnContextDone(t *testing.T) {
	t.Run("before the hand-over", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			b := newTestBuilder(t, DefaultOptions())
			w := newBlockingWriter()
			logger, logs := newTestLogger()
			s := NewWriterSink(w, b, logger, DefaultWriteTimeout)
			defer s.Close()
			// The writer is busy with this record, so the next one cannot be
			// handed over.
			busy := recordAsync(t.Context(), s, testRecord(b, "busy"))
			synctest.Wait()

			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if d := timedRecord(ctx, s, testRecord(b, "cancelled")); d != 0 {
				t.Errorf("Record with a cancelled context took %v, want 0", d)
			}
			if got := logs.get(); len(got) != 1 || !strings.Contains(got[0], "context canceled") {
				t.Errorf("logged %q, want one line about the dropped record", got)
			}

			close(w.release)
			<-busy
			if calls, names := w.written(); calls != 1 || names[0] != "busy" {
				t.Errorf("writer got %d calls with records %v, want only busy", calls, names)
			}
		})
	})
	t.Run("while the write is blocked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			b := newTestBuilder(t, DefaultOptions())
			w := newBlockingWriter()
			logger, logs := newTestLogger()
			s := NewWriterSink(w, b, logger, DefaultWriteTimeout)
			defer s.Close()

			ctx, cancel := context.WithCancel(t.Context())
			start := time.Now()
			done := recordAsync(ctx, s, testRecord(b, "handed-over"))
			synctest.Wait()
			cancel()
			synctest.Wait()
			select {
			case <-done:
			default:
				t.Fatal("Record did not return after its context was cancelled")
			}
			if d := time.Since(start); d != 0 {
				t.Errorf("Record took %v, want 0", d)
			}

			close(w.release)
			synctest.Wait()
			// The handed-over line is written, and the sink did not stall.
			if d := timedRecord(t.Context(), s, testRecord(b, "after")); d != 0 {
				t.Errorf("Record after the release took %v, want 0", d)
			}
			synctest.Wait()
			calls, names := w.written()
			if want := []string{"handed-over", "after"}; calls != 2 || strings.Join(names, ",") != strings.Join(want, ",") {
				t.Errorf("writer got %d calls with records %v, want 2 calls with %v", calls, names, want)
			}
			if got := logs.get(); len(got) != 0 {
				t.Errorf("logged %q, want nothing", got)
			}
		})
	})
}

func TestSinkCloseStopsTheWriter(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			logger, logs := newTestLogger()
			s := NewWriterSink(&lockedBuffer{}, newTestBuilder(t, DefaultOptions()), logger, DefaultWriteTimeout)

			s.Close()

			// The bubble ends only when every goroutine in it has exited, so a
			// writer goroutine that ignored Close fails the test.
			synctest.Wait()
			if got := logs.get(); len(got) != 0 {
				t.Errorf("logged %q, want nothing", got)
			}
		})
	})
	t.Run("with a blocked write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			b := newTestBuilder(t, DefaultOptions())
			w := newBlockingWriter()
			logger, logs := newTestLogger()
			s := NewWriterSink(w, b, logger, DefaultWriteTimeout)
			// One caller waits for its blocked write, the other for its
			// hand-over.
			blocked := recordAsync(t.Context(), s, testRecord(b, "blocked"))
			synctest.Wait()
			waiting := recordAsync(t.Context(), s, testRecord(b, "waiting"))
			synctest.Wait()

			start := time.Now()
			s.Close()
			if d := time.Since(start); d != 0 {
				t.Errorf("Close took %v, want 0", d)
			}
			synctest.Wait()
			for name, done := range map[string]<-chan struct{}{"blocked": blocked, "waiting": waiting} {
				select {
				case <-done:
				default:
					t.Errorf("Record %s did not return after Close", name)
				}
			}
			if d := time.Since(start); d != 0 {
				t.Errorf("Record calls returned after %v, want 0", d)
			}

			// The blocked write is the only goroutine of the sink left. When it
			// returns, the writer takes no more lines and exits.
			close(w.release)
			synctest.Wait()
			if calls, names := w.written(); calls != 1 || names[0] != "blocked" {
				t.Errorf("writer got %d calls with records %v, want only blocked", calls, names)
			}
			if got := logs.get(); len(got) != 0 {
				t.Errorf("logged %q, want nothing", got)
			}
		})
	})
	t.Run("with dropped records", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			b := newTestBuilder(t, DefaultOptions())
			w := newBlockingWriter()
			logger, logs := newTestLogger()
			s := NewWriterSink(w, b, logger, DefaultWriteTimeout)
			s.Record(t.Context(), testRecord(b, "stalls"))
			s.Record(t.Context(), testRecord(b, "dropped-1"))
			s.Record(t.Context(), testRecord(b, "dropped-2"))

			s.Close()

			if got := logs.get(); len(got) != 1 || !strings.Contains(got[0], `"dropped"=2`) {
				t.Errorf("logged %q, want one line that reports 2 dropped records", got)
			}
			close(w.release)
			synctest.Wait()
			if got := logs.get(); len(got) != 1 {
				t.Errorf("logged %q, want only the line from Close", got)
			}
		})
	})
}

func TestSinkRecordAfterCloseDropsAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newTestBuilder(t, DefaultOptions())
		var buf lockedBuffer
		s := NewWriterSink(&buf, b, logr.Discard(), DefaultWriteTimeout)
		s.Close()

		if d := timedRecord(t.Context(), s, testRecord(b, "after-close")); d != 0 {
			t.Errorf("Record after Close took %v, want 0", d)
		}
		synctest.Wait()
		if got := buf.String(); got != "" {
			t.Errorf("wrote %q after Close, want nothing", got)
		}
	})
}

func TestSinkCloseIsIdempotentAndRaceFree(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newTestBuilder(t, DefaultOptions())
		var buf lockedBuffer
		logger, logs := newTestLogger()
		s := NewWriterSink(&buf, b, logger, DefaultWriteTimeout)
		start := time.Now()

		var wg sync.WaitGroup
		for i := range 50 {
			wg.Go(func() { s.Record(t.Context(), testRecord(b, fmt.Sprintf("pcr-%02d", i))) })
		}
		wg.Go(s.Close)
		wg.Go(s.Close)
		wg.Wait()
		s.Close()

		if d := time.Since(start); d != 0 {
			t.Errorf("Record and Close took %v, want 0", d)
		}
		synctest.Wait()
		if out := strings.TrimSuffix(buf.String(), "\n"); out != "" {
			lines := strings.Split(out, "\n")
			for _, line := range lines {
				if !json.Valid([]byte(line)) {
					t.Errorf("line %q is not valid JSON", line)
				}
			}
			if len(lines) > 50 {
				t.Errorf("got %d lines, want at most 50", len(lines))
			}
		}
		if got := logs.get(); len(got) != 0 {
			t.Errorf("logged %q, want nothing", got)
		}
	})
}

// failingWriter fails every Write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("broken pipe")
}

func TestSinkLogsWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newTestBuilder(t, DefaultOptions())
		logger, logs := newTestLogger()
		s := NewWriterSink(failingWriter{}, b, logger, DefaultWriteTimeout)
		defer s.Close()

		if d := timedRecord(t.Context(), s, testRecord(b, "failed")); d != 0 {
			t.Errorf("Record took %v, want 0", d)
		}
		// The writer logs the error after it lets Record return.
		synctest.Wait()

		if got := logs.get(); len(got) != 1 || !strings.Contains(got[0], "broken pipe") {
			t.Errorf("logged %q, want one line with the write error", got)
		}
	})
}
