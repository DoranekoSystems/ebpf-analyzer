package control

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestControlLeaseCancelsOrphanWithoutEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	go WatchControl(ctx, cancel, r, 30*time.Millisecond)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("orphan lease did not expire")
	}
}

func TestControlEOFCancelsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, w := io.Pipe()
	defer r.Close()
	go WatchControl(ctx, cancel, r, time.Hour)
	w.Close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("EOF did not cancel collector")
	}
}
