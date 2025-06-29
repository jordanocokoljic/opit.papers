package main

import (
	"net/http"

	"github.com/jordanocokoljic/opit.papers/internal/xrap"
	"github.com/jordanocokoljic/opit.papers/internal/xrap/xhttp"
)

type Action struct {
	Action string `json:"action"`
}

func main() {
	// server := xrpc.NewServer()

	// xrpc.Register(
	// 	&server, "do",
	// 	xrpc.TransformJSON,
	// 	func(request *Action) xrap.Response {
	// 		return xrap.JSON(map[string]string{"did": request.Action})
	// 	},
	// )

	server := xhttp.NewServer()

	xhttp.Register(
		&server, "POST /do",
		xhttp.TransformJSON,
		func(request *Action) xrap.Response {
			return xrap.JSON(map[string]string{
				"did": request.Action,
			})
		},
	)

	http.ListenAndServe(":8080", &server)
}
