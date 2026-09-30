package netutil

import (
	"context"
	"testing"
	"time"
)

func TestSleepCompletes(t *testing.T) {
	if !Sleep(context.Background(), 10*time.Millisecond) {
		t.Fatal("expected Sleep to complete")
	}
}

func TestSleepCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if Sleep(ctx, time.Second) {
		t.Fatal("expected Sleep to report cancellation")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Sleep did not return promptly: %v", elapsed)
	}
}
