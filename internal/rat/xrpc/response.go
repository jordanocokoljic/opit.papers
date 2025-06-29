package xrpc

import (
	"encoding/json"
	"net/http"
)

type Response interface {
	respond(w http.ResponseWriter)
}

func JSON(body any) jsonResponse {
	return jsonResponse{body}
}

type jsonResponse struct {
	body any
}

func (jr jsonResponse) respond(w http.ResponseWriter) {
	out, err := json.Marshal(jr.body)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}
