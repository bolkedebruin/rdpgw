package kdcproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	krbconfig "github.com/bolkedebruin/gokrb5/v8/config"
	"github.com/jcmturner/gofork/encoding/asn1"
)

const (
	maxLength        = 128 * 1024
	systemConfigPath = "/etc/krb5.conf"
	timeout          = 5 * time.Second
)

type KdcProxyMsg struct {
	Message []byte `asn1:"tag:0,explicit"`
	Realm   string `asn1:"tag:1,optional"`
	Flags   int    `asn1:"tag:2,optional"`
}

type Kdc struct {
	Realm string
	Host  string
	Proto string
	Conn  net.Conn
}

type KerberosProxy struct {
	krb5Config *krbconfig.Config
}

func InitKdcProxy(krb5Conf string) KerberosProxy {
	path := systemConfigPath
	if krb5Conf != "" {
		path = krb5Conf
	}
	cfg, err := krbconfig.Load(path)
	if err != nil {
		log.Fatalf("Cannot load krb5 config %s due to %s", path, err)
	}

	return KerberosProxy{
		krb5Config: cfg,
	}
}

func (k KerberosProxy) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	length := r.ContentLength
	if length == -1 {
		http.Error(w, "Content length required", http.StatusLengthRequired)
		return
	}

	if length > maxLength {
		http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
		return
	}

	data := make([]byte, length)
	_, err := io.ReadFull(r.Body, data)
	if err != nil {
		log.Printf("Error reading from stream: %s", err)
		http.Error(w, "Error reading from stream", http.StatusInternalServerError)
		return
	}

	msg, err := decode(data)
	if err != nil {
		log.Printf("Cannot unmarshal: %s", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(msg.Message) < 4 {
		log.Printf("Invalid kerberos message: shorter than 4-byte length prefix")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	krb5resp, err := k.forward(msg.Realm, msg.Message)
	if err != nil {
		log.Printf("cannot forward to kdc due to %s", err)
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	reply, err := encode(krb5resp)
	if err != nil {
		log.Printf("unable to encode krb5 message due to %s", err)
		http.Error(w, "encoding error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/kerberos")
	w.Write(reply)
}

func (k *KerberosProxy) forward(realm string, data []byte) (resp []byte, err error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("kerberos message too short (%d bytes)", len(data))
	}

	if realm == "" {
		realm = k.krb5Config.LibDefaults.DefaultRealm
	}

	// load udp first as is the default for kerberos
	_, udpKdcs, err := k.krb5Config.GetKDCs(realm, false)
	if err != nil {
		return nil, fmt.Errorf("cannot get udp kdc for realm %s due to %s", realm, err)
	}

	// load tcp
	_, tcpKdcs, err := k.krb5Config.GetKDCs(realm, true)
	if err != nil {
		return nil, fmt.Errorf("cannot get tcp kdc for realm %s due to %s", realm, err)
	}

	var kdcs []Kdc
	for _, host := range udpKdcs {
		kdcs = append(kdcs, Kdc{Realm: realm, Host: ensureDefaultPort(host), Proto: "udp"})
	}
	for _, host := range tcpKdcs {
		kdcs = append(kdcs, Kdc{Realm: realm, Host: ensureDefaultPort(host), Proto: "tcp"})
	}

	if len(kdcs) == 0 {
		return nil, fmt.Errorf("cannot get any kdcs (tcp or udp) for realm %s", realm)
	}

	replies := make(chan []byte, len(kdcs))
	active := 0
	for i := range kdcs {
		conn, err := net.DialTimeout(kdcs[i].Proto, kdcs[i].Host, timeout)
		if err != nil {
			log.Printf("error connecting to %s/%s due to %s, trying next if available", kdcs[i].Proto, kdcs[i].Host, err)
			continue
		}
		conn.SetDeadline(time.Now().Add(timeout))

		// if we proxy over UDP remove the length prefix
		if kdcs[i].Proto == "tcp" {
			_, err = conn.Write(data)
		} else {
			_, err = conn.Write(data[4:])
		}
		if err != nil {
			log.Printf("cannot write packet data to %s/%s due to %s, trying next if available", kdcs[i].Proto, kdcs[i].Host, err)
			conn.Close()
			continue
		}

		kdcs[i].Conn = conn
		active++
		go awaitReply(conn, kdcs[i].Proto == "udp", replies)
	}

	var reply []byte
	for active > 0 {
		r := <-replies
		active--
		if r != nil {
			reply = r
			break
		}
	}

	// close all the connections and drain any remaining goroutines
	for kdc := range kdcs {
		if kdcs[kdc].Conn != nil {
			kdcs[kdc].Conn.Close()
		}
	}
	for active > 0 {
		r := <-replies
		active--
		if reply == nil && r != nil {
			reply = r
		}
	}

	if reply != nil {
		return reply, nil
	}

	return nil, fmt.Errorf("no replies received from kdcs for realm %s", realm)
}

func ensureDefaultPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, "88")
	}
	return host
}

func decode(data []byte) (msg *KdcProxyMsg, err error) {
	var m KdcProxyMsg
	rest, err := asn1.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in request")
	}

	return &m, nil
}

func encode(krb5data []byte) (r []byte, err error) {
	m := KdcProxyMsg{Message: krb5data}
	enc, err := asn1.Marshal(m)
	if err != nil {
		log.Printf("cannot marshal due to %s", err)
		return nil, err
	}
	return enc, nil
}

func awaitReply(conn net.Conn, isUdp bool, reply chan<- []byte) {
	if isUdp {
		buf := make([]byte, maxLength)
		n, err := conn.Read(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("error reading from kdc due to %s", err)
			}
			reply <- nil
			return
		}
		resp := make([]byte, 4+n)
		binary.BigEndian.PutUint32(resp[:4], uint32(n))
		copy(resp[4:], buf[:n])
		reply <- resp
		return
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			log.Printf("error reading from kdc due to %s", err)
		}
		reply <- nil
		return
	}
	msgLen := binary.BigEndian.Uint32(lenBuf[:])
	if msgLen > maxLength {
		log.Printf("kdc response length %d exceeds maximum %d", msgLen, maxLength)
		reply <- nil
		return
	}
	resp := make([]byte, 4+msgLen)
	copy(resp[:4], lenBuf[:])
	if _, err := io.ReadFull(conn, resp[4:]); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			log.Printf("error reading from kdc due to %s", err)
		}
		reply <- nil
		return
	}
	reply <- resp
}
