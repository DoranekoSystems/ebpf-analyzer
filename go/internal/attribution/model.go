package attribution

import (
	"encoding/json"
	"github.com/DoranekoSystems/ebpf-analyzer/internal/origin"
)

// Observation endpoints are always device-side. They are not silently NAT-rewritten.
type Observation struct {
	ConnectionID string `json:"connectionId"`
	ClientIP     string `json:"clientIp"`
	ClientPort   int    `json:"clientPort"`
	ServerIP     string `json:"serverIp"`
	ServerPort   int    `json:"serverPort"`
	From         int64  `json:"validFromEpochMs"`
	To           int64  `json:"validToEpochMs"`
	PID          uint32 `json:"pid"`
	TID          uint32 `json:"tid"`
	UID          uint32 `json:"uid"`
	AppName      string `json:"appName"`
	PackageName  string `json:"packageName,omitempty"`
	ProcessName  string `json:"processName"`
	Closed       bool   `json:"closed"`
}

type Batch struct {
	SchemaVersion int               `json:"schemaVersion"`
	SampledAt     int64             `json:"sampledAtEpochMs"`
	Drops         uint64            `json:"drops"`
	Connections   []Observation     `json:"connections"`
	Packets       json.RawMessage   `json:"packets,omitempty"`
	CopyDrops     uint64            `json:"copyDrops,omitempty"`
	Origins       []origin.Snapshot `json:"origins,omitempty"`
	OriginDrops   uint64            `json:"originDrops,omitempty"`
}
