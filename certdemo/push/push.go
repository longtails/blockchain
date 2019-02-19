package push

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/alfred-zhong/wserver"
	"net/http"
	"time"
)
//change info if need
func PushServer() {
	server := wserver.NewServer(":12345")
	// Define websocket connect url, default "/ws"
	server.WSPath = "/ws"
	// Define push message url, default "/push"
	server.PushPath = "/push"
	// Set AuthToken func to authorize websocket connection, token is sent by
	// client for registe.
	server.AuthToken = func(token string) (userID string, ok bool) {
		// TODO: check if token is valid and calculate userID
		if token == "queryLog" {
			return "queryLog", true
		}

		return "", false
	}

	// Set PushAuth func to check push request. If the request is valid, returns
	// true. Otherwise return false and request will be ignored.
	server.PushAuth = func(r *http.Request) bool {
		// TODO: check if request is valid
		return true
	}

	// Run server
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}

func Push(msg string){
	pushURL := "http://127.0.0.1:12345/push"
	contentType := "application/json"

	pm := wserver.PushMessage{
		UserID:  "queryLog",
		Event:   "queryLog",
		Message: fmt.Sprintf("%s %s",msg, time.Now().Format("2006-01-02 15:04:05.000")),
	}
	b, _ := json.Marshal(pm)

	_,_=http.DefaultClient.Post(pushURL, contentType, bytes.NewReader(b))
}