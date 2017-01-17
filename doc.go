/*Package shttp is an attempt to implement best practices for a hardened and secure http.Server, while getting out of your way as much as possible.

Example Usage

	provider, err := certprovider.SelfSign("testcorp", "127.0.0.1,::1")
	if err != nil {
		log.Fatalln(err.Error())
	}

	s := shttp.NewServerWithRedirect("", provider)

	http.HandleFunc("/", handler)

	if err := s.ListenAndServeTLS(); err != nil {
		log.Fatalln(err.Error())
	}
*/
package shttp
