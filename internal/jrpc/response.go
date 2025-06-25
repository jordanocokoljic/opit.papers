package jrpc

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Response interface {
	respond(w http.ResponseWriter) error
}

func Error(status int, code string) Response {
	return errorResponse{status: status, code: code}
}

type errorResponse struct {
	status int
	code   string
}

func (e errorResponse) respond(w http.ResponseWriter) error {
	w.WriteHeader(e.status)
	fmt.Fprintf(w, `{"error":"%s"}`, e.code)
	return nil
}

func JSON(body any) Response {
	return jsonResponse{body: body}
}

type jsonResponse struct {
	body any
}

func (j jsonResponse) respond(w http.ResponseWriter) error {
	out, err := json.Marshal(j.body)
	if err != nil {
		return err
	}

	w.Write(out)
	return nil
}
