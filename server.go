// +build go1.6,amd64

package shttp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// CertStrategy represents a particular method of certification provisioning
type CertStrategy func(*http.Server) error

// Server is a hardened HTTPS server
type Server struct {
	httpsServer *http.Server
	redirect    bool
}

// NewServer returns a new server object using the given CertStrategy
func NewServer(addr string, certStrategy CertStrategy) (*Server, error) {
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
			MinVersion:   tls.VersionTLS12,
			CipherSuites: cipherSuites,
		},
		// Sane timeouts
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	if err := certStrategy(hs); err != nil {
		return nil, err
	}

	//TODO: Options? Timeout?
	//for _, option := range options {
	//if err := option(hs); err != nil {
	//return nil, err
	//}
	//}

	return &Server{
		httpsServer: hs,
	}, nil
}

// NewServerWithRedirect will create a new server, but will also spin up a
// redirect handler on port 80 to redirect all unencrypted traffic to the HTTPS
// base URL and port you have defined in addr
func NewServerWithRedirect(addr string, certStrategy CertStrategy) (*Server, error) {
	s, err := NewServer(addr, certStrategy)
	if err != nil {
		return nil, err
	}
	s.redirect = true

	return s, nil
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
				panic(err.Error())
			}
		}()
	}
	return s.httpsServer.ListenAndServeTLS("", "")
}

// Manual is the certificate strategy you would choose if you already have your
// own .pem .crt or .key files
func Manual(certFile string, keyFile string) CertStrategy {
	return func(s *http.Server) error {
		if certFile == "" || keyFile == "" {
			return fmt.Errorf("must provide certFile and keyFile")
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		s.TLSConfig.Certificates = make([]tls.Certificate, 1)
		s.TLSConfig.Certificates[0] = cert
		return nil
	}
}

// LetsEncrypt is a certificate strategy using ACME and the LetsEncrypt service
// certDir is a directory used for caching certificates, and must be accessible/
// writeable to the server's user/group.
func LetsEncrypt(domain string, certDir string) CertStrategy {
	return func(s *http.Server) error {
		if domain == "" || certDir == "" {
			return fmt.Errorf("must provide certFile and keyFile")
		}

		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache(certDir),
		}

		s.TLSConfig.GetCertificate = certManager.GetCertificate
		return nil
	}
}

// SelfCert will generate a self-signed certificat for the server.
// organization is the self-selected signing org (required)
// host is a comma-separated list of IPs/domains to generate the signature for
//   DEFAULT: "127.0.0.1,::1,example.com"
func SelfCert(organization string, host string) CertStrategy {
	// note: code shamelessly cribbed from /src/crypto/tls/generate_cert.go, and is
	// equivalent to the following:
	// go run generate_cert.go --host <host string> --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
	// but with a custom organization
	return func(s *http.Server) error {
		if host == "" {
			host = "127.0.0.1,::1,example.com"
		}

		if organization == "" {
			return fmt.Errorf("Must provide organization")
		}

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		notBefore, err := time.Parse("Jan 2 15:04:05 2006", "Jan 1 00:00:00 1970")
		if err != nil {
			return err
		}
		notAfter := notBefore.Add(100000 * time.Hour)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("failed to generate serial number: %s", err)
		}

		cert := x509.Certificate{
			IsCA:         true,
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{organization},
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		hosts := strings.Split(host, ",")
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				cert.IPAddresses = append(cert.IPAddresses, ip)
			} else {
				cert.DNSNames = append(cert.DNSNames, h)
			}
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &privKey.PublicKey, privKey)
		if err != nil {
			return err
		}

		var certPEMBlock bytes.Buffer
		var keyPEMBlock bytes.Buffer

		pem.Encode(&certPEMBlock, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		pem.Encode(&keyPEMBlock, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

		pair, err := tls.X509KeyPair(certPEMBlock.Bytes(), keyPEMBlock.Bytes())
		if err != nil {
			return err
		}
		s.TLSConfig.Certificates = []tls.Certificate{pair}
		return nil
	}
}
