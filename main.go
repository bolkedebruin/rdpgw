package main

import (
	"crypto/tls"
	"net/http/httputil"
	"os"
	//"time"

	//"bytes"
	"fmt"
	"log"
	//"strings"
	// "io"
	"net/http"
	//"net/http/httputil"
	//"math/rand"
	//"encoding/binary"
	//"encoding/base64"
)


/*
func handleConnection(s *MySession) {
	inData := make([]byte, 4096)

	for {
		size, err := s.buffIn.Read(inData)
		if err != nil {
			s.inConn.Close()
			s.outConn.Close()
			fmt.Println(err)
		}
		fmt.Printf("Bytes read on IN %d\n", size)
	}
}*/

/*
func MethodOverride(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Method)
		dump, _ := httputil.DumpRequest(r, false)
		fmt.Printf("%q\n", dump)

		headerKey := "Rdg-Connection-Id"
		connId := r.Header.Get(headerKey)
		if connId != "" {
			s.guid = connId
		}
		auth := r.Header.Get("Authorization")
		fmt.Printf("Connection ID: %s\n", s.guid)

		if strings.Contains(auth,"NTLMX") {
			/*var msg_req_b []byte
			base64.StdEncoding.Decode(msg_req_b, []byte(auth[strings.Index(auth,"NTLM")+6:]))

			msg_type := binary.LittleEndian.Uint32(msg_req_b[0:4])
			fmt.Printf("Message type %v\n", msg_type)
			if msg_type == 1 {
				var nonce [8]byte
				r := make([]byte, 8)
				rand.Read(r)
				copy(nonce[:], r)

				sig_buf := new(bytes.Buffer)
				var signature [8]byte
				binary.Write(sig_buf, binary.LittleEndian, "NTLMSSP\000")
				copy(signature[:], sig_buf.Bytes())

				zero := make([]byte, 7)
				pad := make([]byte, 2)

				rand.Read(nonce)

				buf := new(bytes.Buffer)
				msg := NtlmChallenge{
					signature,
					uint32(0x02),
					0,
					0,
					0,
					[]byte(),
					nonce,
					0,
					0
				}
				_ := binary.Write(buf, binary.LittleEndian, msg)
				header := "NTLM" + base64.StdEncoding.EncodeToString(buf.Bytes())
				w.Header().Set("WWW-Authenticate", header)
				w.WriteHeader(401)
				w.Write([]byte("Unauthorized.\n"))
				fmt.Println("Unauthorized")
				return
			}
		} else {
			_, _, ok := r.BasicAuth()

			if !ok && !s.hasIn {
				w.Header().Set("WWW-Authenticate", `Basic realm="rdpgw"`)
				w.WriteHeader(401)
				w.Write([]byte("Unauthorized.\n"))
				fmt.Println("Unauthorized")
				return
			}
		}

		if r.Method == "RDG_OUT_DATA" {
			fmt.Println("Hijacking OUT")
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
				return
			}
			conn, bufrw, err := hj.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.outConn = conn
			s.buffOut = bufrw

			if !s.hasOut {
				fmt.Printf("Creating OUT and sending seed\n")
				s.hasOut = true
				seed := make([]byte, 100)
				rand.Read(seed)
				bufrw.WriteString("HTTP/1.1 200 OK\r\n")
				fmt.Fprintf(bufrw, "Date: %s\r\n", time.Now().Format(time.RFC1123))
				bufrw.WriteString("Content-Type: application/octet-stream\r\n")
				bufrw.WriteString("Content-Length: 0\r\n")
				bufrw.WriteString(crlf)
				bufrw.Write(seed)
				bufrw.Flush()
				return
			} else {
				fmt.Printf("Handle OUT\n")
				handleConnection(s)
				return
			}
		}

		if r.Method == "RDG_IN_DATA" {
			fmt.Println("Hijacking IN")
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
				return
			}
			conn, bufrw, err := hj.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.inConn = conn
			s.buffIn = bufrw

			if !s.hasIn {
				fmt.Printf("Creating IN and sending seed\n")
				s.hasIn = true
				seed := make([]byte, 100)
				rand.Read(seed)
				bufrw.WriteString("HTTP/1.1 200 OK\r\n")
				fmt.Fprintf(bufrw, "Date: %s\r\n", time.Now().Format(time.RFC1123))
				bufrw.WriteString("Content-Type: application/octet-stream\r\n")
				bufrw.WriteString("Content-Length: 0\r\n")
				bufrw.WriteString(crlf)
				bufrw.Write(seed)
				bufrw.Flush()
				return
			} else {
				fmt.Printf("Handle IN\n")

				handleConnection(s)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
*/

func HelloServer(w http.ResponseWriter, req *http.Request) {
	dump, _ := httputil.DumpRequest(req, true)
	fmt.Println(dump)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
	// io.WriteString(w, "This is an example server.\n")
}

func main() {
	fmt.Println("Hello!")
	mux := http.NewServeMux()
	mux.HandleFunc("*", HelloServer)

	w, err := os.OpenFile("tls-secrets.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	cfg := &tls.Config{
		KeyLogWriter: w,
	}
	cert, err := tls.LoadX509KeyPair("server.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	server := http.Server{
		Addr: ":8000",
		Handler: Upgrade(mux),
		TLSConfig: cfg,
	}
	err = server.ListenAndServeTLS("","")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}