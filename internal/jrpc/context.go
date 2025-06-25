package jrpc

import (
	"context"
	"log/slog"
	"net/http"
)

type baseContext struct {
	Log *slog.Logger
	r   *http.Request
	w   http.ResponseWriter
}

func (bc *baseContext) Context() context.Context {
	return bc.r.Context()
}

type Ctx[T any] struct {
	*baseContext
	Request *T
}
