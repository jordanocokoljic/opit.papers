package jrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

type Transformer[T any] func(json.RawMessage) (*T, error)
type Action[T any] func(context.Context, *slog.Logger, *T) Response

type methodDescription struct {
	transform func(json.RawMessage) (any, error)
	action    func(context.Context, *slog.Logger, any) Response
}

func RegisterMethod[T any](
	s *Server, key string,
	transform Transformer[T], action Action[T],
) {
	if _, ok := s.methods[key]; ok {
		panic(fmt.Errorf("method already registered against key '%s'", key))
	}

	s.methods[key] = methodDescription{
		transform: func(rm json.RawMessage) (any, error) {
			return transform(rm)
		},
		action: func(ctx context.Context, log *slog.Logger, r any) Response {
			return action(ctx, log, r.(*T))
		},
	}
}

func Transform[T any](rm json.RawMessage) (*T, error) {
	var request T
	err := json.Unmarshal(rm, &request)
	return &request, err
}
