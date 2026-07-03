package main

import (
	"io"
	"net/http"
)

func DrainAndClose(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		},
	)
}

// Wraps a route so that if user is logged in, return
// func Authenticated(next http.Handler) http.Handler {
// 	return http.Handl
// }
