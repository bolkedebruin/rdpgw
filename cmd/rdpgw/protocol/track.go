package protocol

import (
	"fmt"
	"sync"
)

var (
	Connections        = map[string]*Monitor{}
	connectionsMu      sync.RWMutex
)

type Monitor struct {
	Processor *Processor
	Tunnel    *Tunnel
}

const (
	ctlDisconnect = -1
)

func RegisterTunnel(t *Tunnel, p *Processor) {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()

	Connections[t.Id] = &Monitor{
		Processor: p,
		Tunnel:    t,
	}
}

func RemoveTunnel(t *Tunnel) {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()

	delete(Connections, t.Id)
}

func Disconnect(id string) error {
	connectionsMu.RLock()
	m, ok := Connections[id]
	connectionsMu.RUnlock()

	if !ok {
		return fmt.Errorf("%s connection does not exist", id)
	}
	m.Processor.ctl <- ctlDisconnect
	return nil
}
