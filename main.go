package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	port := flag.Int("port", 443, "port to listen on for incoming connections")
	certFile := flag.String("certfile", "server.pem", "public key certificate file")
	keyFile := flag.String("keyfile", "key.pem", "private key file")

	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatal("Both certfile and keyfile need to be specified")
	}

	//mux := http.NewServeMux()
	//mux.HandleFunc("*", HelloServer)

	log.Printf("Starting remote desktop gateway server")
	cfg := &tls.Config{}
	tlsDebug := os.Getenv("SSLKEYLOGFILE")
	if tlsDebug != "" {
		w, err := os.OpenFile(tlsDebug, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Cannot open key log file %s for writing %s", tlsDebug, err)
		}
		log.Printf("Key log file set to: %s", tlsDebug)
		cfg.KeyLogWriter = w
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	server := http.Server{
		Addr:      ":" + strconv.Itoa(*port),
		Handler:   Upgrade(nil),
		TLSConfig: cfg,
	}

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
