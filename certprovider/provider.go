package certprovider

import "crypto/tls"

// Provider represents a particular method of certification provisioning or
// retrieval
type Provider func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
