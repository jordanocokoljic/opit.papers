package xrpc

import (
	"io"
	"net/http"

	"github.com/jordanocokoljic/opit.papers/internal/xrap"
)

type Server struct {
	procs map[string]procedure
}

func NewServer() Server {
	return Server{
		procs: make(map[string]procedure),
	}
}

// ServeHTTP implements [net/http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "POST")
		return
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	proc, found := s.procs[r.URL.Path[1:]]
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":{"code":"XRPC_READ_ERROR"}}`))
		return
	}

	request, err := proc.transform(r.Header, body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":{"code":"XRPC_TRANSFORM_FAILURE"}}`))
		return
	}

	result := proc.apply(r.Context(), request)

	var ra resultAdapter
	err = xrap.Finalize(&ra, result)
	if err != nil {
		// TODO: handle the case that we can't build the response
		return
	}

	ra.write(w)
}
