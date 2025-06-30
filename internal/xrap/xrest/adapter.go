package xrest

import (
	"encoding/json"
	"net/http"
)

type resultAdapter struct {
	bundle struct {
		ContentType string
		Body        []byte
		Status      int
	}
}

func (a *resultAdapter) JSON(body any) error {
	marshalled, err := json.Marshal(body)
	if err != nil {
		return err
	}

	a.bundle.ContentType = "application/json"
	a.bundle.Body = marshalled
	return nil
}

func (a *resultAdapter) Status(status int) error {
	a.bundle.Status = status
	return nil
}

func (a *resultAdapter) Error(err error) error {
	a.bundle.ContentType = ""
	a.bundle.Body = []byte("Sorry, an internal server error occurred.")
	a.bundle.Status = http.StatusInternalServerError
	return nil
}

func (a *resultAdapter) write(w http.ResponseWriter) {
	if ct := a.bundle.ContentType; ct != "" {
		w.Header().Set("Content-Type", a.bundle.ContentType)
	}

	if status := a.bundle.Status; status != 0 {
		w.WriteHeader(status)
	}

	w.Write(a.bundle.Body)
}
