package certprovider

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
	"strings"
	"time"
)

// SelfSign will generate a self-signed certificat for the server.
// organization is the self-selected signing org (required)
// host is a comma-separated list of IPs/domains to generate the signature for
//   DEFAULT: "127.0.0.1,::1,example.com"
func SelfSign(organization string, host string) (func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	// note: code shamelessly cribbed from /src/crypto/tls/generate_cert.go, and is
	// equivalent to the following:
	// go run generate_cert.go --host <host string> --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
	// but with a custom organization
	if host == "" {
		host = "127.0.0.1,::1,example.com"
	}

	if organization == "" {
		return nil, fmt.Errorf("Must provide organization")
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	notBefore, err := time.Parse("Jan 2 15:04:05 2006", "Jan 1 00:00:00 1970")
	if err != nil {
		return nil, err
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
		return nil, err
	}

	var certPEMBlock bytes.Buffer
	var keyPEMBlock bytes.Buffer

	pem.Encode(&certPEMBlock, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	pem.Encode(&keyPEMBlock, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	pair, err := tls.X509KeyPair(certPEMBlock.Bytes(), keyPEMBlock.Bytes())
	if err != nil {
		return nil, err
	}

	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &pair, nil
	}, nil
}
