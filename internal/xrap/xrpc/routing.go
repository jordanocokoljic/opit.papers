package xrpc

import (
	"encoding/json"
	"net/http"

	"github.com/jordanocokoljic/opit.papers/internal/xrap"
)

type Transform[T any] func(header http.Header, body []byte) (*T, error)
type Apply[T any] func(request *T) xrap.Response

type procedure struct {
	transform func(header http.Header, body []byte) (any, error)
	apply     func(request any) xrap.Response
}

func Register[T any](s *Server, key string, t Transform[T], a Apply[T]) {
	s.procs[key] = procedure{
		transform: func(header http.Header, body []byte) (any, error) {
			return t(header, body)
		},
		apply: func(request any) xrap.Response {
			return a(request.(*T))
		},
	}
}

func TransformJSON[T any](_ http.Header, body []byte) (*T, error) {
	var request T
	err := json.Unmarshal(body, &request)
	return &request, err
}
