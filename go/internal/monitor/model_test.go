package monitor

import (
	"encoding/binary"
	"fmt"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/attribution"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/origin"
	"testing"
)

func TestDecodeAndOwnership(t *testing.T) {
	data := make([]byte, 40)
	data[0] = 0x45
	data[9] = 6
	copy(data[12:16], []byte{10, 0, 2, 15})
	copy(data[16:20], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(data[20:22], 12345)
	binary.BigEndian.PutUint16(data[22:24], 443)
	p, ok := Decode(data, 100, 150)
	if !ok || p.Source != "10.0.2.15:12345" || p.Destination != "1.2.3.4:443" || p.OriginalLength != 100 {
		t.Fatalf("decode: %+v", p)
	}
	c := attribution.Observation{ConnectionID: "a", ClientIP: "10.0.2.15", ClientPort: 12345, ServerIP: "1.2.3.4", ServerPort: 443, From: 100, To: 200, PID: 12}
	s := NewState()
	s.Add(nil, []Packet{p})
	if s.Packets[0].ConnectionID != "" {
		t.Fatal("invented owner")
	}
	s.Add([]attribution.Observation{c}, nil)
	if s.Packets[0].ConnectionID != "a" {
		t.Fatal("late owner missing")
	}
	other := c
	other.ConnectionID = "late-overlap"
	s.Add([]attribution.Observation{other}, nil)
	if s.Packets[0].ConnectionID != "" {
		t.Fatal("late ambiguity did not revoke attribution")
	}
	p.At = 200
	s.Add(nil, []Packet{p})
	if s.Packets[1].ConnectionID != "" {
		t.Fatal("end boundary reused")
	}
	c.ConnectionID = "b"
	s = NewState()
	a := c
	a.ConnectionID = "a"
	p.At = 150
	s.Add([]attribution.Observation{a, c}, []Packet{p})
	if s.Packets[0].ConnectionID != "" {
		t.Fatal("ambiguous owner guessed")
	}
	data[6] = 0x20
	p, ok = Decode(data, 40, 150)
	if !ok || p.Protocol != "IP" {
		t.Fatal("fragment assigned transport ports")
	}
}

func TestBoundedSnapshot(t *testing.T) {
	s := NewState()
	s.Add(nil, make([]Packet, 600))
	if len(s.Packets) != 512 {
		t.Fatal("packet history unbounded")
	}
	if err := Write(t.TempDir()+"/monitor.json", s.Snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestOriginsPersistAcrossFlowUpdatesAndStayBounded(t *testing.T) {
	s := NewState()
	s.AddOrigins([]origin.Snapshot{{ConnectionID: "known", Stack: []byte{1, 2, 3}}})
	s.Add([]attribution.Observation{{ConnectionID: "known"}}, nil)
	s.AddOrigins(nil)
	s.Add([]attribution.Observation{{ConnectionID: "known", Closed: true}}, nil)
	if len(s.Origins) != 1 || len(s.Origins[0].Stack) != 3 {
		t.Fatal("one-shot stack lost on update")
	}
	for i := 0; i < 128; i++ {
		s.AddOrigins([]origin.Snapshot{{ConnectionID: fmt.Sprint(i)}})
	}
	if len(s.Origins) != 128 || s.EvictedOrigins != 1 {
		t.Fatal("stack retention is not bounded")
	}
}

func TestIOEventsDoNotOverwriteConnectionOrOtherThreads(t *testing.T) {
	s := NewState()
	s.AddOrigins([]origin.Snapshot{{ConnectionID: "flow", TID: 1}})
	for i := 1; i <= 130; i++ {
		s.AddOrigins([]origin.Snapshot{{ConnectionID: "flow", EventID: fmt.Sprint(i), CapturedAtBootNS: fmt.Sprint(i), TID: uint32(i + 10), Stack: []byte{byte(i)}}})
	}
	if len(s.IOEvents) != 128 || s.EvictedIOEvents != 2 || len(s.Origins) != 1 || s.Origins[0].TID != 1 {
		t.Fatal("independent retention failed")
	}
	if s.IOEvents[0].EventID != "3" || s.IOEvents[0].TID != 13 || s.IOEvents[127].Stack[0] != 130 {
		t.Fatal("event identity/context lost")
	}
	s.AddOrigins([]origin.Snapshot{s.IOEvents[0]})
	if len(s.IOEvents) != 128 || s.EvictedIOEvents != 2 {
		t.Fatal("duplicate event counted twice")
	}
}
