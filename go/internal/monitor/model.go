// Package monitor contains the passive capture format, separate from proxy history.
package monitor

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/attribution"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/origin"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

type Packet struct {
	InterfaceIndex int    `json:"interfaceIndex"`
	At             int64  `json:"atEpochMs"`
	Source         string `json:"source"`
	Destination    string `json:"destination"`
	Protocol       string `json:"protocol"`
	Data           []byte `json:"data"`
	OriginalLength int    `json:"originalLength"`
	ConnectionID   string `json:"connectionId,omitempty"`
}

// Decode only assigns ports for unfragmented IPv4/IPv6 with a direct TCP/UDP header.
// Unsupported extension headers and fragments remain unattributed raw packets.
func Decode(data []byte, original int, at int64) (Packet, bool) {
	p := Packet{At: at, OriginalLength: original, Data: append([]byte(nil), data...), Protocol: "IP"}
	var src, dst netip.Addr
	var proto byte
	var offset int
	fragmented := false
	if len(data) >= 20 && data[0]>>4 == 4 {
		offset = int(data[0]&15) * 4
		if offset < 20 || offset > len(data) {
			return p, false
		}
		src = netip.AddrFrom4([4]byte(data[12:16]))
		dst = netip.AddrFrom4([4]byte(data[16:20]))
		proto = data[9]
		fragmented = binary.BigEndian.Uint16(data[6:8])&0x3fff != 0
	} else if len(data) >= 40 && data[0]>>4 == 6 {
		offset = 40
		proto = data[6]
		src = netip.AddrFrom16([16]byte(data[8:24]))
		dst = netip.AddrFrom16([16]byte(data[24:40]))
	} else {
		return p, false
	}
	p.Source, p.Destination = src.String(), dst.String()
	if !fragmented && (proto == 6 || proto == 17) && len(data) >= offset+8 {
		p.Protocol = "TCP"
		if proto == 17 {
			p.Protocol = "UDP"
		}
		p.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(data[offset:offset+2])).String()
		p.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(data[offset+2:offset+4])).String()
	}
	return p, true
}

type Snapshot struct {
	SchemaVersion      int                       `json:"schemaVersion"`
	Mode               string                    `json:"mode"`
	UpdatedAt          int64                     `json:"updatedAtEpochMs"`
	Running            bool                      `json:"running"`
	Drops              uint64                    `json:"drops"`
	CopyDrops          uint64                    `json:"copyDrops"`
	EvictedConnections uint64                    `json:"evictedConnections"`
	Connections        []attribution.Observation `json:"connections"`
	Packets            []Packet                  `json:"packets"`
	Origins            []origin.Snapshot         `json:"origins"`
	OriginDrops        uint64                    `json:"originDrops"`
	EvictedOrigins     uint64                    `json:"evictedOrigins"`
	IOEvents           []origin.Snapshot         `json:"ioEvents"`
	EvictedIOEvents    uint64                    `json:"evictedIoEvents"`
}

type State struct {
	Snapshot
	flows map[string]attribution.Observation
}

func NewState() *State {
	return &State{Snapshot: Snapshot{SchemaVersion: 1, Mode: "passive", Running: true, Connections: []attribution.Observation{}, Packets: []Packet{}, Origins: []origin.Snapshot{}, IOEvents: []origin.Snapshot{}}, flows: map[string]attribution.Observation{}}
}

// Origin snapshots arrive once, sometimes before a connection is established.
// Keep them independently of later connection updates; cap raw stack memory.
func (s *State) AddOrigins(incoming []origin.Snapshot) {
	for _, o := range incoming {
		if o.EventID != "" {
			found := false
			for i := range s.IOEvents {
				if s.IOEvents[i].EventID == o.EventID {
					s.IOEvents[i] = o
					found = true
					break
				}
			}
			if !found {
				s.IOEvents = append(s.IOEvents, o)
			}
			continue
		}
		found := false
		for i := range s.Origins {
			if s.Origins[i].ConnectionID == o.ConnectionID {
				s.Origins[i] = o
				found = true
				break
			}
		}
		if !found {
			s.Origins = append(s.Origins, o)
		}
	}
	sort.Slice(s.IOEvents, func(i, j int) bool {
		a, _ := strconv.ParseUint(s.IOEvents[i].CapturedAtBootNS, 10, 64)
		b, _ := strconv.ParseUint(s.IOEvents[j].CapturedAtBootNS, 10, 64)
		return a < b
	})
	if len(s.IOEvents) > 128 {
		s.EvictedIOEvents += uint64(len(s.IOEvents) - 128)
		s.IOEvents = append([]origin.Snapshot(nil), s.IOEvents[len(s.IOEvents)-128:]...)
	}
	if len(s.Origins) > 128 {
		s.EvictedOrigins += uint64(len(s.Origins) - 128)
		s.Origins = append([]origin.Snapshot(nil), s.Origins[len(s.Origins)-128:]...)
	}
}

func (s *State) Add(connections []attribution.Observation, packets []Packet) {
	for _, c := range connections {
		s.flows[c.ConnectionID] = c
	}
	s.Connections = s.Connections[:0]
	for _, c := range s.flows {
		s.Connections = append(s.Connections, c)
	}
	sort.Slice(s.Connections, func(i, j int) bool { return s.Connections[i].From > s.Connections[j].From })
	if len(s.Connections) > 2000 {
		for _, c := range s.Connections[2000:] {
			delete(s.flows, c.ConnectionID)
			s.EvictedConnections++
		}
		s.Connections = s.Connections[:2000]
	}
	s.Packets = append(s.Packets, packets...)
	if len(s.Packets) > 512 {
		s.Packets = append([]Packet(nil), s.Packets[len(s.Packets)-512:]...)
	}
	type endpoints struct{ from, to string }
	index := map[endpoints][]attribution.Observation{}
	for _, c := range s.Connections {
		a, err := netip.ParseAddr(c.ClientIP)
		if err != nil {
			continue
		}
		b, err := netip.ParseAddr(c.ServerIP)
		if err != nil {
			continue
		}
		from := netip.AddrPortFrom(a, uint16(c.ClientPort)).String()
		to := netip.AddrPortFrom(b, uint16(c.ServerPort)).String()
		index[endpoints{from, to}] = append(index[endpoints{from, to}], c)
		index[endpoints{to, from}] = append(index[endpoints{to, from}], c)
	}
	// Revisit copies when a late flow arrives, including previously matched copies:
	// another matching lifetime must revoke attribution, not leave a guessed PID.
	for i := range s.Packets {
		p := &s.Packets[i]
		p.ConnectionID = ""
		if p.Protocol != "TCP" {
			continue
		}
		match := ""
		for _, c := range index[endpoints{p.Source, p.Destination}] {
			if p.At < c.From || p.At >= c.To {
				continue
			}
			if match != "" {
				match = ""
				break
			}
			match = c.ConnectionID
		}
		p.ConnectionID = match
	}
}

func Write(path string, s Snapshot) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(data) > 16*1024*1024 {
		return fmt.Errorf("monitor snapshot too large")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".monitor-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// Windows readers (including Java) may briefly open without delete sharing.
	// Keep the previous valid snapshot visible and retry the atomic replacement.
	for attempt := 0; attempt < 40; attempt++ {
		err = os.Rename(f.Name(), path)
		if err == nil || !os.IsPermission(err) {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
	return err
}
