package xhttp

import "net/http"

type Server struct {
	mux *http.ServeMux
}

func NewServer() Server {
	return Server{
		mux: http.NewServeMux(),
	}
}

// ServeHTTP implements [net/http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
