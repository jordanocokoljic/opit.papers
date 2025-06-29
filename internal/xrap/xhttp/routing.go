package xhttp

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/jordanocokoljic/opit.papers/internal/xrap"
)

type Transform[T any] func(request *http.Request) (*T, error)
type Apply[T any] func(request *T) xrap.Response

func Register[T any](s *Server, pattern string, t Transform[T], a Apply[T]) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		request, err := t(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		xrap.Finalize(w, a(request))
	})
}

func TransformJSON[T any](r *http.Request) (*T, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var request T
	err = json.Unmarshal(body, &request)
	return &request, err
}
