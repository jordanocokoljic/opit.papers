package xrpc

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jordanocokoljic/opit.papers/internal/xrap"
)

type Transform[T any] func(header http.Header, body []byte) (*T, error)
type Apply[T any] func(ctx context.Context, request *T) xrap.Result

type procedure struct {
	transform func(header http.Header, body []byte) (any, error)
	apply     func(ctx context.Context, request any) xrap.Result
}

func Register[T any](
	s *Server, key string,
	transform Transform[T], apply Apply[T],
) {
	s.procs[key] = procedure{
		transform: func(header http.Header, body []byte) (any, error) {
			return transform(header, body)
		},
		apply: func(ctx context.Context, request any) xrap.Result {
			return apply(ctx, request.(*T))
		},
	}
}

func TransformJSON[T any](_ http.Header, body []byte) (*T, error) {
	var request T
	err := json.Unmarshal(body, &request)
	return &request, err
}
