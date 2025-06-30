package xrest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/jordanocokoljic/opit.papers/internal/xrap"
)

type Transform[T any] func(request *http.Request) (*T, error)
type Apply[T any] func(ctx context.Context, request *T) xrap.Result

func Register[T any](
	s *Server, pattern string,
	transform Transform[T], apply Apply[T],
) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		request, err := transform(r)
		if err != nil {
			switch n := err.(type) {
			case ConvertibleError:
				w.WriteHeader(n.status)
				w.Write(n.message)
			default:
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Sorry, an internal server error occurred."))
			}

			return
		}

		result := apply(r.Context(), request)

		var ra resultAdapter
		err = xrap.Finalize(&ra, result)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Sorry, an internal server error occurred."))
			return
		}

		ra.write(w)
	})
}

func TransformJSON[T any](r *http.Request) (*T, error) {
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		return nil, ConvertibleError{
			inner:   errors.New("incorrect Content-Type for TransformJson"),
			status:  http.StatusUnsupportedMediaType,
			message: []byte("415 Unsupported Media Type"),
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var request T
	err = json.Unmarshal(body, &request)
	return &request, err
}
