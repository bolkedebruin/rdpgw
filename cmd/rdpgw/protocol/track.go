package protocol

import (
	"time"
)

var Connections map[string]*GatewayConnection

type GatewayConnection struct {
	PacketHandler *Processor
	SessionInfo   *SessionInfo
	Since         time.Time
	IsWebsocket   bool
}

func RegisterConnection(connId string, h *Processor, s *SessionInfo) {
	if Connections == nil {
		Connections = make(map[string]*GatewayConnection)
	}

	Connections[connId] = &GatewayConnection{
		PacketHandler: h,
		SessionInfo:   s,
		Since:         time.Now(),
	}
}

func CloseConnection(connId string) {
	delete(Connections, connId)
}
