// Package netutil holds small networking helpers shared across the proxies.
package netutil

import (
	"context"
	"fmt"
	"time"
)

const unit = 1024

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

// Format bytes to human-readable string
func FormatBytes(b int64) string {
	if b < unit {
		return fmt.Sprintf("%d Bytes", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	// Use 1024 Radix: KB, MB, GB, TB, PB
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), units[exp])
}
