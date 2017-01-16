package certprovider

import (
	"crypto/tls"
	"fmt"
)

// Manual is the certificate provider you would choose if you already have your
// own .pem .crt or .key files
func Manual(certFile string, keyFile string) (func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("must provide certFile and keyFile")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}, nil
}
