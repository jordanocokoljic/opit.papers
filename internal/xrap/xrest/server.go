package xrest

import (
	"log/slog"
	"net/http"
)

type Server struct {
	log *slog.Logger
	mux *http.ServeMux
}

func NewServer(log *slog.Logger) Server {
	return Server{
		log: log,
		mux: http.NewServeMux(),
	}
}

// ServeHTTP implements [net/http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
