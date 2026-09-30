// Package netutil holds small networking helpers shared across the proxies.
package netutil

import (
	"context"
	"time"
)

// Sleep waits for d, returning false early when ctx is cancelled.
func Sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
