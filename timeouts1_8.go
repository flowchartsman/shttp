// +build go1.8

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

	if s.IdleTimeout == 0 {
		s.IdleTimeout = 120 * time.Second
	}
}
