package main

import (
	"net/http"

	"github.com/jordanocokoljic/opit.papers/internal/rat/xrpc"
)

func main() {
	rpc := xrpc.NewServer()

	xrpc.Register(
		&rpc, "dothing",
		xrpc.TransformJSON,
		func(request *int) xrpc.Response {
			return xrpc.JSON(map[string]int{"got": *request})
		},
	)

	http.ListenAndServe(":8080", &rpc)
}
