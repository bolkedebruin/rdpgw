package protocol

var Connections map[string]*Monitor

type Monitor struct {
	Processor *Processor
	Tunnel    *Tunnel
}

func RegisterConnection(h *Processor, t *Tunnel) {
	if Connections == nil {
		Connections = make(map[string]*Monitor)
	}

	Connections[t.RDGId] = &Monitor{
		Processor: h,
		Tunnel:    t,
	}
}

func RemoveConnection(connId string) {
	delete(Connections, connId)
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
