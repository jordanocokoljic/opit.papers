package xrpc

import (
	"encoding/json"
	"net/http"
)

type resultAdapter struct {
	bundle struct {
		Result json.RawMessage `json:"result"`
	}
}

func (a *resultAdapter) JSON(body any) error {
	marshalled, err := json.Marshal(body)
	if err != nil {
		return err
	}

	a.bundle.Result = marshalled
	return nil
}

func (a *resultAdapter) Status(status int) error {
	return nil
}

func (a *resultAdapter) Error(err error) error {
	return nil
}

func (a *resultAdapter) write(w http.ResponseWriter) {
	marshalled, err := json.Marshal(a.bundle)
	if err != nil {
		// TODO: Handle marshalling errors gracefully
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(marshalled)
}
