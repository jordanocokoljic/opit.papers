package jrpc

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

type Server struct {
	log     *slog.Logger
	methods map[string]methodDescription
}

// NewServer will create a new Server with the provided logger.
func NewServer(log *slog.Logger) Server {
	return Server{
		log:     log,
		methods: make(map[string]methodDescription),
	}
}

// ServeHTTP implements [net/http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.log.Warn(
			"request received with invalid method",
			"method", r.Method,
		)

		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		s.log.Warn(
			"request received with invalid Content-Type",
			"content_type", ct,
		)

		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	if r.URL.Path != "/rpc" {
		s.log.Warn(
			"request received with invalid path",
			"path", r.URL.Path,
		)

		w.WriteHeader(http.StatusNotFound)
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		s.log.Warn(
			"unable to read full request body",
			"error", err.Error(),
		)

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var call struct {
		Method    string          `json:"method"`
		Arguments json.RawMessage `json:"arguments"`
	}

	err = json.Unmarshal(content, &call)
	if err != nil {
		s.log.Warn(
			"unable to unmarshal request content into RPC call",
			"error", err.Error(),
		)

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	description, ok := s.methods[call.Method]
	if !ok {
		s.log.Warn(
			"unable to find requested RPC method",
			"requested_method", call.Method,
		)

		w.WriteHeader(http.StatusNotFound)
		return
	}

	log := s.log.With("rpc_method", call.Method)

	request, err := description.transform(call.Arguments)
	if err != nil {
		s.log.Warn(
			"unable to transform RPC call arguments into request type",
			"rpc_method", call.Method,
		)

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = description.action(r.Context(), log, request).respond(w)
	if err != nil {
		s.log.Error(
			"failed to send response to client",
			"error", err.Error(),
		)
	}
}
