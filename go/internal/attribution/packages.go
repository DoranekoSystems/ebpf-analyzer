package attribution

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PackageResolver watches Android's UID mapping, including installs during capture.
// A failed read keeps the last good mapping and is retried after a short backoff.
type PackageResolver struct {
	Path     string
	Names    map[uint32][]string
	modified time.Time
	size     int64
	checked  time.Time
	retry    time.Time
}

func (r *PackageResolver) Refresh(now time.Time) error {
	if now.Before(r.retry) {
		return nil
	}
	info, err := os.Stat(r.Path)
	if err != nil {
		r.retry = now.Add(5 * time.Second)
		return err
	}
	if r.Names != nil && info.ModTime().Equal(r.modified) && info.Size() == r.size && now.Sub(r.checked) < 5*time.Second {
		return nil
	}
	data, err := os.ReadFile(r.Path)
	if err != nil {
		r.retry = now.Add(5 * time.Second)
		return err
	}
	names := map[uint32][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		uid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			continue
		}
		names[uint32(uid)] = append(names[uint32(uid)], fields[0])
	}
	if len(names) == 0 {
		r.retry = now.Add(5 * time.Second)
		return fmt.Errorf("empty or invalid package list: %s", r.Path)
	}
	for _, values := range names {
		sort.Strings(values)
	}
	r.Names, r.modified, r.size, r.checked = names, info.ModTime(), info.Size(), now
	r.retry = time.Time{}
	return nil
}
