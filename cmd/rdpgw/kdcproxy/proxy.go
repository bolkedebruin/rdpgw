package kdcproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	krbconfig "github.com/bolkedebruin/gokrb5/v8/config"
	"github.com/jcmturner/gofork/encoding/asn1"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

const (
	maxLength        = 128 * 1024
	systemConfigPath = "/etc/krb5.conf"
	timeout          = 5 * time.Second
)

// errRealmNotServed is returned for a realm that is not in krb5.conf
var errRealmNotServed = errors.New("realm not served by this proxy")

type KdcProxyMsg struct {
	Message []byte `asn1:"tag:0,explicit"`
	Realm   string `asn1:"tag:1,optional"`
	Flags   int    `asn1:"tag:2,optional"`
}

type Kdc struct {
	Realm string
	Host  string
	Proto string
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

	krb5resp, err := k.forward(msg.Realm, msg.Message)
	if errors.Is(err, errRealmNotServed) {
		log.Printf("kdc proxy: refusing request for realm %q: %s", msg.Realm, err)
		http.Error(w, "Realm not served", http.StatusForbidden)
		return
	}
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

// forward sends one KERB-KDC-REQ message to the realm's KDCs and returns the reply.
// data is the message as MS-KKDCP carries it: a 4-byte big-endian length, then the
// Kerberos message. The reply is returned in the same form.
//
// KDCs are tried one at a time, TCP first. gokrb5 numbers the KDCs it returns from 1, so
// they're walked in that order rather than used as slice indices. A KDC keeps a TCP
// connection open after replying, so exactly one length-prefixed reply is read.
func (k *KerberosProxy) forward(realm string, data []byte) (resp []byte, err error) {
	if realm == "" {
		realm = k.krb5Config.LibDefaults.DefaultRealm
	}
	if !k.servesRealm(realm) {
		return nil, errRealmNotServed
	}
	if len(data) < 4 || int(binary.BigEndian.Uint32(data[:4])) != len(data)-4 {
		return nil, fmt.Errorf("malformed request for realm %s", realm)
	}

	var kdcs []Kdc
	for _, proto := range []string{"tcp", "udp"} {
		count, hosts, err := k.krb5Config.GetKDCs(realm, proto == "tcp")
		if err != nil {
			log.Printf("no %s kdc for realm %s: %s", proto, realm, err)
			continue
		}
		for i := 1; i <= count; i++ {
			if host, ok := hosts[i]; ok {
				kdcs = append(kdcs, Kdc{Realm: realm, Host: host, Proto: proto})
			}
		}
	}
	if len(kdcs) == 0 {
		return nil, fmt.Errorf("cannot get any kdcs (tcp or udp) for realm %s", realm)
	}

	for _, kdc := range kdcs {
		resp, err := exchange(kdc, data)
		if err != nil {
			log.Printf("kdc %s/%s for realm %s failed: %s, trying next if available", kdc.Proto, kdc.Host, realm, err)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("no replies received from kdcs for realm %s", realm)
}

// servesRealm reports whether requests for realm are forwarded: the default
// realm and the realms in the [realms] section of krb5.conf. The realm comes
// from an unauthenticated client. With dns_lookup_kdc any other realm would
// make the proxy look up the KDCs in the client's own DNS, and send the
// request to whatever host and port those records name.
func (k *KerberosProxy) servesRealm(realm string) bool {
	if realm == "" {
		return false
	}
	if realm == k.krb5Config.LibDefaults.DefaultRealm {
		return true
	}
	for _, r := range k.krb5Config.Realms {
		if r.Realm == realm {
			return true
		}
	}
	return false
}

func exchange(kdc Kdc, data []byte) ([]byte, error) {
	conn, err := net.DialTimeout(kdc.Proto, kdc.Host, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if kdc.Proto == "udp" {
		if _, err := conn.Write(data[4:]); err != nil {
			return nil, err
		}
		buf := make([]byte, maxLength)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		resp := make([]byte, 4+n)
		binary.BigEndian.PutUint32(resp, uint32(n))
		copy(resp[4:], buf[:n])
		return resp, nil
	}

	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n > maxLength {
		return nil, fmt.Errorf("reply of %d bytes is too large", n)
	}
	resp := make([]byte, 4+n)
	copy(resp, prefix[:])
	if _, err := io.ReadFull(conn, resp[4:]); err != nil {
		return nil, err
	}
	return resp, nil
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
