package certprovider

import (
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/acme/autocert"
)

// LetsEncrypt is a certificate provider using ACME and the LetsEncrypt service
// certDir is a directory used for caching certificates, and must be accessible/
// writeable to the server's user/group.
func LetsEncrypt(domain string, certDir string) (func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	if domain == "" || certDir == "" {
		return nil, fmt.Errorf("must provide domain and certDir")
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(certDir),
	}

	return certManager.GetCertificate, nil
}
