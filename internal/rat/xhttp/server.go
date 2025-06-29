package xhttp

import "net/http"

type Server struct{}

func NewServer() Server {
	return Server{}
}

// ServeHTTP implements [net/http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {

}
