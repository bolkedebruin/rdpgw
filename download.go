package main

import (
	"encoding/hex"
	"github.com/patrickmn/go-cache"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func handleRdpDownload(w http.ResponseWriter, r *http.Request) {
	seed := make([]byte, 16)
	rand.Read(seed)
	fn := hex.EncodeToString(seed) + ".rdp"

	rand.Read(seed)
	token := hex.EncodeToString(seed)

	tokens.Set(token, token, cache.DefaultExpiration)

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")
	http.ServeContent(w, r, fn, time.Now(), strings.NewReader(
		"full address:s:localhost\r\n"+
			"gatewayhostname:s:localhost\r\n"+
			"gatewaycredentialssource:i:5\r\n"+
			"gatewayusagemethod:i:1\r\n"+
			"gatewayaccesstoken:s:" + token + "\r\n"))
}
