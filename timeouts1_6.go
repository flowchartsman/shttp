// +build go1.6,!go1.7

package shttp

import (
	"net/http"
	"time"
)

func applyTimeouts(s *http.Server) {
	if s.ReadTimeout == 0 {
		s.ReadTimeout = 5 * time.Second
	}

	if s.WriteTimeout == 0 {
		s.WriteTimeout = 10 * time.Second
	}
}
