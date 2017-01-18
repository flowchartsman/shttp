// +build go1.7,!go1.8

package shttp

import (
	"net/http"
	"time"
)

func applyTimeouts(s *http.Server) {
	// ReadTimeout breaks HTTP/2 in go1.7, so only use it if it's been explicitly
	// disabled
	// ref: https://github.com/golang/go/issues/16450
	if s.TLSNextProto != nil && len(s.TLSNextProto) == 0 && s.ReadTimeout == 0 {
		s.ReadTimeout = 5 * time.Second
	}

	if s.WriteTimeout == 0 {
		s.WriteTimeout = 10 * time.Second
	}
}
