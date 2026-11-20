package audit

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// DefaultWriteTimeout is how long [WriterSink.Record] waits for its line to be
// written.
const DefaultWriteTimeout = 2 * time.Second

// errNotTaken is the reason a record is dropped when the write timeout passes
// before the writer takes its line and no write is in progress.
var errNotTaken = errors.New("the write timeout passed before the audit writer took the record")

// errClosed is the reason a record is dropped at or after Close.
var errClosed = errors.New("the audit sink is closed")

// Recorder writes audit records.
type Recorder interface {
	// Record writes rec. It returns when the line is written, when the write
	// timeout passes, or when ctx is done. It never returns an error.
	Record(ctx context.Context, rec Record)
}

// WriterSink is a [Recorder] that writes each record as one line to an
// io.Writer, such as stdout. One goroutine owns the writer, so lines are never
// interleaved.
//
// [NewWriterSink] starts the writer goroutine and [WriterSink.Close] stops it.
// The sink does not follow a context, so records emitted while the manager
// shuts down are still written. Close it after the manager has stopped. After
// Close, Record drops each record at once.
//
// A write that is still blocked when a Record call times out stalls the sink.
// While the sink is stalled, Record drops each record at once and counts it.
// When the blocked write returns, the sink logs the count and takes records
// again. Close logs the count if the sink is still stalled.
//
// Every other dropped record is logged on its own line with its event, request
// namespace, name and uid, and certificate fingerprint when it has one: a
// record that does not encode, a record whose context is done before the
// hand-over, a record whose write timeout passes before the hand-over while no
// write is in progress, and every record dropped at or after Close.
type WriterSink struct {
	w            io.Writer
	b            *Builder
	logger       logr.Logger
	writeTimeout time.Duration
	// writes hands a line from Record to the writer goroutine. It is
	// unbuffered, so a line that was handed over is in the writer's hands.
	writes chan *pendingWrite
	// done is closed by Close. It stops the writer goroutine and releases
	// every Record call that waits.
	done      chan struct{}
	closeOnce sync.Once

	// mu guards closed, writing, stalled, dropped and pendingWrite.completed.
	//
	// Invariant: stalled is set only while a write has not completed, and the
	// writer clears stalled, under the same lock, when it marks that write
	// completed. So a stall always ends when the blocked write returns.
	// Record sets stalled after a timeout only if its own handed-over write
	// is not completed, or, when it timed out before the hand-over, only if
	// writing is true.
	// Close clears stalled and reports the open count. After Close, stalled
	// is never set again, and closed makes every Record drop at once. The
	// writer checks closed before each Write, so no line is written after
	// Close.
	mu      sync.Mutex
	closed  bool
	writing bool
	stalled bool
	dropped int
}

// pendingWrite is one line that Record handed over to the writer goroutine.
type pendingWrite struct {
	line []byte
	// rec is the record of line. The writer names it when it drops line.
	rec Record
	// completed is set when the Write call returned. It is guarded by
	// WriterSink.mu.
	completed bool
	// done is closed after completed is set.
	done chan struct{}
}

var _ Recorder = (*WriterSink)(nil)

// NewWriterSink returns a sink that encodes records with b and writes them to
// w, and starts its writer goroutine. A writeTimeout of zero or less is
// [DefaultWriteTimeout]. Call [WriterSink.Close] to stop the goroutine.
func NewWriterSink(w io.Writer, b *Builder, logger logr.Logger, writeTimeout time.Duration) *WriterSink {
	if writeTimeout <= 0 {
		writeTimeout = DefaultWriteTimeout
	}
	s := &WriterSink{
		w:            w,
		b:            b,
		logger:       logger,
		writeTimeout: writeTimeout,
		writes:       make(chan *pendingWrite),
		done:         make(chan struct{}),
	}
	go s.writeLoop()
	return s
}

// Close stops the writer goroutine and logs the number of records dropped
// since the last report, if there are any. It returns at once, also while a
// write is blocked: that write finishes in the background, and then the writer
// goroutine exits. Close can be called more than once and concurrently with
// Record.
func (s *WriterSink) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		// Close takes over the report of a stall that is still open.
		dropped := s.dropped
		s.stalled, s.dropped = false, 0
		s.mu.Unlock()
		close(s.done)
		if dropped > 0 {
			s.logger.Error(nil, "audit records were dropped before the audit sink closed", "dropped", dropped)
		}
	})
}

// Record encodes rec and hands the line to the writer goroutine. It returns
// when the line is written, when the write timeout passes, or when ctx is
// done. A line that was handed over is written even when Record returned
// first. After Close, Record drops rec at once. Errors are logged, not
// returned.
func (s *WriterSink) Record(ctx context.Context, rec Record) {
	s.mu.Lock()
	closed := s.closed
	stalled := s.stalled && !closed
	if stalled {
		s.dropped++
	}
	s.mu.Unlock()
	if closed {
		s.logDrop(errClosed, rec)
		return
	}
	if stalled {
		return
	}

	line, err := s.b.Encode(rec)
	if err != nil {
		s.logDrop(err, rec)
		return
	}
	pw := &pendingWrite{line: line, rec: rec, done: make(chan struct{})}
	timer := time.NewTimer(s.writeTimeout)
	defer timer.Stop()

	select {
	case s.writes <- pw:
	case <-timer.C:
		s.mu.Lock()
		closed = s.closed
		counted := s.writing && !closed
		if counted {
			s.stalled = true
			s.dropped++
		}
		s.mu.Unlock()
		switch {
		case closed:
			s.logDrop(errClosed, rec)
		case !counted:
			s.logDrop(errNotTaken, rec)
		}
		return
	case <-ctx.Done():
		s.logDrop(ctx.Err(), rec)
		return
	case <-s.done:
		s.logDrop(errClosed, rec)
		return
	}

	select {
	case <-pw.done:
	case <-timer.C:
		s.mu.Lock()
		if !pw.completed && !s.closed {
			s.stalled = true
		}
		s.mu.Unlock()
	case <-ctx.Done():
	case <-s.done:
	}
}

func (s *WriterSink) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case pw := <-s.writes:
			s.write(pw)
		}
	}
}

// write writes pw.line, unless the sink is closed. The select in writeLoop
// can take a line in the same instant as Close, so write drops that line and
// logs it.
func (s *WriterSink) write(pw *pendingWrite) {
	s.mu.Lock()
	closed := s.closed
	if closed {
		pw.completed = true
	} else {
		s.writing = true
	}
	s.mu.Unlock()
	if closed {
		close(pw.done)
		s.logDrop(errClosed, pw.rec)
		return
	}

	_, err := s.w.Write(pw.line)

	s.mu.Lock()
	s.writing = false
	pw.completed = true
	stalled, dropped := s.stalled, s.dropped
	s.stalled, s.dropped = false, 0
	s.mu.Unlock()
	close(pw.done)

	if err != nil {
		s.logger.Error(err, "failed to write an audit record")
	}
	if stalled {
		s.logger.Error(nil, "an audit record write was blocked past the write timeout", "dropped", dropped)
	}
}

func (s *WriterSink) logDrop(err error, rec Record) {
	keysAndValues := []any{"event", rec.Event,
		"namespace", rec.Request.Namespace, "name", rec.Request.Name, "uid", rec.Request.UID}
	if rec.Certificate != nil {
		keysAndValues = append(keysAndValues, "fingerprint", rec.Certificate.Fingerprint)
	}
	s.logger.Error(err, "audit record dropped", keysAndValues...)
}
