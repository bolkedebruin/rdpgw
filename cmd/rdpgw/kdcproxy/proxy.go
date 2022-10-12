package kdcproxy

import (
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

type KdcProxyMsg struct {
	Message []byte `asn1:"tag:0,explicit"`
	Realm   string `asn1:"tag:1,optional"`
	Flags   int    `asn1:"tag:2,optional"`
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
	if err != nil {
		log.Printf("cannot forward to kdc due to %s", err)
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	reply, err := encode(krb5resp)
	if err != nil {
		log.Printf("unable to encode krb5 message due to %s", err)
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/kerberos")
	w.Write(reply)
}

func (k *KerberosProxy) forward(realm string, data []byte) (resp []byte, err error) {
	if realm == "" {
		realm = k.krb5Config.LibDefaults.DefaultRealm
	}

	// load udp first as is the default for kerberos
	c, kdcs, err := k.krb5Config.GetKDCs(realm, false)
	if err != nil || c < 1 {
		return nil, fmt.Errorf("cannot get kdc for realm %s due to %s", realm, err)
	}

	for i := range kdcs {
		conn, err := net.Dial("tcp", kdcs[i])
		if err != nil {
			log.Printf("error connecting to %s due to %s, trying next if available", kdcs[i], err)
			continue
		}
		conn.SetDeadline(time.Now().Add(timeout))

		_, err = conn.Write(data)
		if err != nil {
			log.Printf("cannot write packet data to %s due to %s, trying next if available", kdcs[i], err)
			conn.Close()
			continue
		}

		// todo check header
		resp, err = io.ReadAll(conn)
		if err != nil {
			log.Printf("error reading from kdc %s due to %s, trying next if available", kdcs[i], err)
			conn.Close()
			continue
		}
		conn.Close()

		return resp, nil
	}

	return nil, fmt.Errorf("no kdcs found for realm %s", realm)
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
