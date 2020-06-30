package main

import (
	"net/http"
	"strconv"
)

const (
	HttpOK = "HTTP/1.1 200 OK\r\n"
	MethodRDGIN  = "RDG_IN_DATA"
	MethodRDGOUT = "RDG_OUT_DATA"
)

// httpError is like the http.Error with WebSocket context exception.
func httpError(w http.ResponseWriter, body string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	w.Write([]byte(body))
}

