// Package logging provides a non-blocking log sink. Console output can stall
// indefinitely — cmd.exe suspends writes while the user has text selected — so
// log lines are queued and drained by one goroutine. A stalled terminal can no
// longer block the goroutines that produce log lines.
package logging

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultQueueSize is the number of queued lines kept before new lines are
// dropped.
const DefaultQueueSize = 1024

// MaxLineBytes bounds one queued line so an oversized message cannot fill the
// whole queue by itself.
const MaxLineBytes = 8 * 1024

// DefaultCloseTimeout bounds how long Close waits for the queue to drain. A
// stalled terminal must never keep the process alive at exit.
const DefaultCloseTimeout = 300 * time.Millisecond

// batchBytes is the amount of queued data the drain goroutine writes in one
// call before starting a new batch.
const batchBytes = 16 * 1024

// logTimeFormat matches config.LogFlags (log.Ldate | log.Lmicroseconds).
const logTimeFormat = "2006/01/02 15:04:05.000000"

// Sink is an io.Writer that queues what it receives and writes it from a
// single goroutine. Write never blocks: when the queue is full the line is
// dropped and counted instead.
type Sink struct {
	ch      chan []byte
	writer  io.Writer
	dropped atomic.Uint64
	stop    chan struct{}
	done    chan struct{}
	closed  atomic.Bool
	once    sync.Once
}

// New starts a sink writing to w. A capacity of zero or less uses
// DefaultQueueSize; a nil w discards everything.
func New(w io.Writer, capacity int) *Sink {
	if w == nil {
		w = io.Discard
	}
	if capacity <= 0 {
		capacity = DefaultQueueSize
	}
	s := &Sink{
		ch:     make(chan []byte, capacity),
		writer: w,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go s.run()
	return s
}

// Write queues p and reports len(p) written. It never blocks and never returns
// an error: a line that does not fit is dropped and counted so the caller
// keeps running while the terminal is stalled.
func (s *Sink) Write(p []byte) (int, error) {
	n := len(p)
	if n == 0 {
		return 0, nil
	}
	if s.closed.Load() {
		s.dropped.Add(1)
		return n, nil
	}
	if n > MaxLineBytes {
		p = p[:MaxLineBytes]
	}
	line := make([]byte, len(p))
	copy(line, p)
	select {
	case s.ch <- line:
	default:
		s.dropped.Add(1)
	}
	return n, nil
}

// Dropped reports how many lines were dropped since the last drain.
func (s *Sink) Dropped() uint64 { return s.dropped.Load() }

// Close stops accepting new lines and waits up to timeout for the queue to
// drain. A stalled writer must not keep the process alive, so exceeding the
// timeout discards the remaining lines and returns. Close is idempotent.
func (s *Sink) Close(timeout time.Duration) {
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.stop)
		if timeout <= 0 {
			timeout = DefaultCloseTimeout
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-s.done:
		case <-timer.C:
		}
	})
}

func (s *Sink) run() {
	defer close(s.done)

	batch := make([]byte, 0, batchBytes)
	for {
		select {
		case <-s.stop:
			s.drain(batch)
			return
		case line := <-s.ch:
			batch = append(batch, line...)
			s.flush(s.fill(batch))
			batch = batch[:0]
		}
	}
}

// fill appends lines that are already queued so the next write covers as many
// of them as one call allows.
func (s *Sink) fill(batch []byte) []byte {
	for len(batch) < batchBytes {
		select {
		case line := <-s.ch:
			batch = append(batch, line...)
		default:
			return batch
		}
	}
	return batch
}

// drain writes everything still queued after Close. No new lines can be
// queued, so the loop ends once the channel is empty.
func (s *Sink) drain(batch []byte) {
	for {
		batch = s.fill(batch)
		if len(batch) == 0 {
			return
		}
		s.flush(batch)
		batch = batch[:0]
	}
}

// flush writes batch and then, if lines were dropped while the writer was
// stalled, one summary line. A failed write keeps the dropped count so the
// next flush reports it again.
func (s *Sink) flush(batch []byte) {
	if len(batch) > 0 {
		if _, err := s.writer.Write(batch); err != nil {
			return
		}
	}
	if n := s.dropped.Swap(0); n > 0 {
		line := fmt.Sprintf("%s [log] dropped %d lines (console output stalled)\n",
			time.Now().Format(logTimeFormat), n)
		if _, err := s.writer.Write([]byte(line)); err != nil {
			s.dropped.Add(n)
		}
	}
}
