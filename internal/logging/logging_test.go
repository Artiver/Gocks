package logging

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingWriter blocks every Write until release is closed, simulating a
// console that has stopped consuming output.
type blockingWriter struct {
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	buf     bytes.Buffer
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{release: make(chan struct{})}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *blockingWriter) releaseAll() {
	w.once.Do(func() { close(w.release) })
}

func (w *blockingWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestWriteNeverBlocksOnStalledWriter(t *testing.T) {
	w := newBlockingWriter()
	s := New(w, 2)
	defer s.Close(time.Second)
	defer w.releaseAll()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			if n, err := s.Write([]byte("line\n")); n != 5 || err != nil {
				t.Errorf("Write = %d, %v; want 5, nil", n, err)
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked while the writer was stalled")
	}

	if s.Dropped() == 0 {
		t.Fatal("expected dropped lines when the queue is full")
	}
}

func TestWritesKeepOrderAndAreFlushed(t *testing.T) {
	var buf bytes.Buffer
	s := New(&buf, DefaultQueueSize)

	var want strings.Builder
	for i := 0; i < 100; i++ {
		line := fmt.Sprintf("line %d\n", i)
		want.WriteString(line)
		if _, err := s.Write([]byte(line)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	s.Close(time.Second)

	if got := buf.String(); got != want.String() {
		t.Fatalf("sink output mismatch:\ngot:  %q\nwant: %q", got, want.String())
	}
}

func TestCloseTimesOutOnStalledWriter(t *testing.T) {
	w := newBlockingWriter()
	s := New(w, 4)
	defer w.releaseAll()

	s.Write([]byte("first\n"))
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	s.Close(50 * time.Millisecond)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("Close took %s with a stalled writer", elapsed)
	}
}

func TestWriteAfterCloseIsDropped(t *testing.T) {
	var buf bytes.Buffer
	s := New(&buf, 4)
	s.Close(time.Second)

	n, err := s.Write([]byte("late\n"))
	if n != 5 || err != nil {
		t.Fatalf("Write after Close = %d, %v; want 5, nil", n, err)
	}
	if s.Dropped() != 1 {
		t.Fatalf("Dropped = %d; want 1", s.Dropped())
	}
}

func TestOversizedLineIsTruncated(t *testing.T) {
	var buf bytes.Buffer
	s := New(&buf, 4)

	long := bytes.Repeat([]byte("a"), MaxLineBytes+500)
	n, err := s.Write(long)
	if n != len(long) || err != nil {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(long))
	}

	s.Close(time.Second)

	if buf.Len() > MaxLineBytes {
		t.Fatalf("sink kept %d bytes; want at most %d", buf.Len(), MaxLineBytes)
	}
}

func TestDroppedSummaryIsReported(t *testing.T) {
	w := newBlockingWriter()
	s := New(w, 1)
	defer w.releaseAll()

	s.Write([]byte("first\n"))
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 50; i++ {
		s.Write([]byte("dropped me\n"))
	}

	w.releaseAll()
	time.Sleep(50 * time.Millisecond)
	s.Close(time.Second)

	if out := w.String(); !strings.Contains(out, "dropped") {
		t.Fatalf("output does not report dropped lines: %q", out)
	}
}

func TestConcurrentWritesAreSafe(t *testing.T) {
	var buf bytes.Buffer
	s := New(&buf, 64)

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_, _ = s.Write([]byte(fmt.Sprintf("g%d line %d\n", g, i)))
			}
		}(g)
	}
	wg.Wait()
	s.Close(2 * time.Second)

	if buf.Len() == 0 {
		t.Fatal("no output written")
	}
}
