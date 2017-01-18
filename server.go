// +build go1.6,amd64

package shttp

import (
	"crypto/tls"
	"net"
	"net/http"
)

// Server is a hardened HTTPS server
type Server struct {
	httpsServer *http.Server
	redirect    bool
}

// NewServer returns a new server object using the given certificate provider
func NewServer(addr string, certProvider func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)) *Server {
	hs := &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			// Causes servers to use Go's default ciphersuite preferences,
			// which are tuned to avoid attacks. Does nothing on clients.
			PreferServerCipherSuites: true,
			// Only use curves which have assembly implementations
			CurvePreferences: curvePreferences,
			// Compatibility loss is worth Modern configuration
			// see: https://wiki.mozilla.org/Security/Server_Side_TLS
			MinVersion:     tls.VersionTLS12,
			CipherSuites:   cipherSuites,
			GetCertificate: certProvider,
		},
	}

	//TODO: Options? Timeout?
	//for _, option := range options {
	//if err := option(hs); err != nil {
	//return nil, err
	//}
	//}

	return &Server{
		httpsServer: hs,
	}
}

// NewServerWithRedirect will create a new server, but will also spin up a
// redirect handler on port 80 to redirect all unencrypted traffic to the HTTPS
// base URL and port you have defined in addr
func NewServerWithRedirect(addr string, certProvider func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)) *Server {
	s := NewServer(addr, certProvider)
	s.redirect = true
	return s
}

// ListenAndServeTLS begins serving with this particular server configuration
// and optionally spins up a redirect handler in another goroutine.
// Unlike net/http.Server, this does not take any arguments, since a certificate
// strategy will already have been provided
func (s *Server) ListenAndServeTLS() error {
	if s.redirect {

		var redirectURL string

		serverAddr := s.httpsServer.Addr
		if serverAddr == "" {
			serverAddr = ":https"
		}

		host, port, err := net.SplitHostPort(serverAddr)

		if err != nil {
			return err
		}

		if host == "" {
			redirectURL = "https://127.0.0.1"
		} else {
			redirectURL = "https://" + host
		}

		switch port {
		case "", "https":
		default:
			redirectURL = redirectURL + ":" + port
		}

		go func() {
			err := http.ListenAndServe(host+":http", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				http.Redirect(w, req, redirectURL+req.RequestURI, http.StatusMovedPermanently)
			}))
			if err != nil {
				panic("error in serving the http -> https redirect:" + err.Error())
			}
		}()
	}

	// Apply version-specific best practices
	applyTimeouts(s.httpsServer)

	// Start the server
	return s.httpsServer.ListenAndServeTLS("", "")
}

// StdServer returns the underlying *http.Server for further configuration.
// Obviously, this can be used to undo most of the best practices this library
// attempts to make standard, so it should be used with caution, sparingly, and
// only when necessary
func (s *Server) StdServer() *http.Server {
	return s.httpsServer
}
