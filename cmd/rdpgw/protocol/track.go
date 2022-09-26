package protocol

import "fmt"

var Connections map[string]*Monitor

type Monitor struct {
	Processor *Processor
	Tunnel    *Tunnel
}

const (
	ctlDisconnect = -1
)

func RegisterTunnel(t *Tunnel, p *Processor) {
	if Connections == nil {
		Connections = make(map[string]*Monitor)
	}

	Connections[t.Id] = &Monitor{
		Processor: p,
		Tunnel:    t,
	}
}

func RemoveTunnel(t *Tunnel) {
	delete(Connections, t.Id)
}

func Disconnect(id string) error {
	if Connections == nil {
		return fmt.Errorf("%s connection does not exist", id)
	}

	if m, ok := Connections[id]; !ok {
		m.Processor.ctl <- ctlDisconnect
		return nil
	}

	return fmt.Errorf("%s connection does not exist", id)
}

// CalculateSpeedPerSecond calculate moving average.
/*
func CalculateSpeedPerSecond(connId string) (in int, out int) {
	now := time.Now().UnixMilli()

	c := Connections[connId]
	total := int64(0)
	for _, v := range c.Tunnel.BytesReceived {
		total += v
	}
	in = int(total / (now - c.TimeStamp) * 1000)

	total = int64(0)
	for _, v := range c.BytesSent {
		total += v
	}
	out = int(total / (now - c.TimeStamp))

	return in, out
}
*/
