package web

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"log"
	"net/http"
)

func TokenInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request", http.StatusMethodNotAllowed)
		return
	}

	tokens, ok := r.URL.Query()["access_token"]
	if !ok || len(tokens[0]) < 1 {
		log.Printf("Missing access_token in request")
		http.Error(w, "access_token missing in request", http.StatusBadRequest)
		return
	}

	token := tokens[0]

	info, err := security.UserInfo(context.Background(), token)
	if err != nil {
		log.Printf("Token validation failed due to %s", err)
		http.Error(w, fmt.Sprintf("token validation failed due to %s", err), http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err = json.NewEncoder(w).Encode(info); err != nil {
		log.Printf("Cannot encode json due to %s", err)
		http.Error(w, "cannot encode json", http.StatusInternalServerError)
		return
	}
}
