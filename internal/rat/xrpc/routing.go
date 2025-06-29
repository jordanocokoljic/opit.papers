package xrpc

import "encoding/json"

type Transform[T any] func(body []byte) (*T, error)
type Apply[T any] func(request *T) Response

type procedure struct {
	transform func(body []byte) (any, error)
	apply     func(request any) Response
}

func Register[T any](s *Server, key string, t Transform[T], a Apply[T]) {
	s.procs[key] = procedure{
		transform: func(body []byte) (any, error) {
			return t(body)
		},
		apply: func(request any) Response {
			return a(request.(*T))
		},
	}
}

func TransformJSON[T any](body []byte) (*T, error) {
	var request T
	err := json.Unmarshal(body, &request)
	return &request, err
}
