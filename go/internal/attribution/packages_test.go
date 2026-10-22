package attribution

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPackageRefreshDuringCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packages.list")
	now := time.Now()
	r := PackageResolver{Path: path}
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("old.app 10001 0 /data/user/0/old.app\n")
	if err := r.Refresh(now); err != nil {
		t.Fatal(err)
	}
	write("old.app 10001 0 /data/user/0/old.app\nnew.app 10203 0 /data/user/0/new.app\n")
	if err := r.Refresh(now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if got := r.Names[10203]; len(got) != 1 || got[0] != "new.app" {
		t.Fatalf("new install unresolved: %v", got)
	}
	write("")
	if err := r.Refresh(now.Add(time.Second)); err == nil {
		t.Fatal("empty read accepted")
	}
	if len(r.Names[10203]) != 1 {
		t.Fatal("lost last good mapping")
	}
	write("replacement.app 10204 0 /data/user/0/replacement.app\n")
	if err := r.Refresh(now.Add(7 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(r.Names[10203]) != 0 || len(r.Names[10204]) != 1 {
		t.Fatal("install/uninstall mapping stale")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(now.Add(8 * time.Second)); err == nil {
		t.Fatal("missing file accepted")
	}
	if len(r.Names[10204]) != 1 {
		t.Fatal("lost mapping after read failure")
	}
}
