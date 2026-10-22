package control

import (
	"bufio"
	"context"
	"io"
	"time"
)

// WatchControl bounds the lifetime of an orphaned collector even when adbd fails to
// deliver stdin EOF after a host transport disconnect. The caller owns the reader.
func WatchControl(ctx context.Context, cancel context.CancelFunc, r io.Reader, lease time.Duration) {
	activity := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64), 64)
		for scanner.Scan() {
			if scanner.Text() != "ping" {
				break
			}
			select {
			case activity <- true:
			case <-ctx.Done():
				return
			}
		}
		select {
		case activity <- false:
		case <-ctx.Done():
		}
	}()
	timer := time.NewTimer(lease)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			cancel()
			return
		case alive := <-activity:
			if !alive {
				cancel()
				return
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(lease)
		}
	}
}
