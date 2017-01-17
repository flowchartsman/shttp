# shttp
[![GoDoc](https://godoc.org/github.com/alaska/shttp?status.svg)](https://godoc.org/github.com/alaska/shttp) [![Go Report Card](https://goreportcard.com/badge/github.com/alaska/shttp)](https://goreportcard.com/report/github.com/alaska/shttp)

---

Let's make solid, encrypted Golang webservers easy!

## What
This package is an attempt to track best practices for a hardened and secure `net/http` server while getting out of your way as much as possible.

## Why
I was initially inspired to write this little helper library by [Filippo Valsorda](https://github.com/FiloSottile)'s [Gopher Academy blog post](https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/) on self serving go TLS directly to the Internet. `net/http`'s defaults are tuned more for local services, after all, which isn't good enough for exposure to the big bad Internet, which is full of unsavory types. It should be easy to make a server that is resistent to the usual sorts of jerk-offery.  Now that `crypto/tls` is not slow<sup>1</sup>, it should be the default whenever possible.

Later, while I was looking into self-certification and support for [Let's Encrypt](https://letsencrypt.org/getting-started/), I came across [autocert](https://godoc.org/golang.org/x/crypto/acme/autocert), and [a proposal](https://github.com/golang/go/issues/17053) to add it to the standard library (or at least docs on how to use it). Incorporating this along with rudimentary self-signing support seemed like a natural extension to my "make good crypto easy" idea, so I added that in too.

I was also very influenced by [George Tankersley](https://github.com/gtank)'s, excellent [cryptopasta](https://github.com/gtank/cryptopasta) anti-library, introduced during his talk at GopherCon 2016.

## How
```go
import (
        "fmt"
        "log"
        "net/http"

        "github.com/alaska/shttp"
        "github.com/alaska/shttp/certprovider"
)

func handler(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "You've accessed %s\n", r.URL.Path[1:])
}

func main() {
        provider, err := certprovider.SelfSign("testcorp", "127.0.0.1,::1")
        if err != nil {
                log.Fatalln(err.Error())
        }

        s := shttp.NewServerWithRedirect(":https", provider)

        http.HandleFunc("/", handler)

        if err := s.ListenAndServeTLS(); err != nil {
                log.Fatalln(err.Error())
        }
}

```

```
$ curl -k https://localhost/stuff
You've accessed stuff
$ curl -k http://localhost/things
<a href="https://127.0.0.1/things">Moved Permanently</a>.

$ curl -kL http://localhost/things
You've accessed things

$ openssl s_client -showcerts -cipher ECDHE-RSA-AES256-GCM-SHA384 -connect 127.0.0.1:443 </dev/null
CONNECTED(00000003)
depth=0 O = testcorp
verify error:num=18:self signed certificate
verify return:1
depth=0 O = testcorp
verify error:num=10:certificate has expired
notAfter=May 29 16:00:00 1981 GMT
verify return:1
depth=0 O = testcorp
notAfter=May 29 16:00:00 1981 GMT
verify return:1
---
Certificate chain
 0 s:/O=testcorp
   i:/O=testcorp
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIQJqtozqpBq/KgQDnrAo4ISDANBgkqhkiG9w0BAQsFADAT
MREwDwYDVQQKEwh0ZXN0Y29ycDAeFw03MDAxMDEwMDAwMDBaFw04MTA1MjkxNjAw
MDBaMBMxETAPBgNVBAoTCHRlc3Rjb3JwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAw3CLrQtbwUHq9FbxE0wkOO6r2YnO7eFNEp9Xzru2/Bo4OFFLLca/
7pRM+Z/lzu6terB2aa7W5jhFp1ePyTvruEftSaRsrPLAeoJ9ayBrJSjn5vMMLo8I
q278nrdvPqmtFSh/AchxFAdZAAngRcOrC0hHs/1D8qZ/6krU9jpWB7L8oTLOX8hB
KEUAN0mkFfdD2/qs2kjJw8JPgOg3gY13qcLfQ4gqiuwujotifEsnxly95qLmoHTJ
HiwfVjwof9ZLyicXvW+EeSd+wANVessPtolWQChnP8/KcYOjX7QXnUWCAKKe55jA
oXGlU44Qymzj5Pqd9hNSTfXBa5mMCFJbfQIDAQABo1swWTAOBgNVHQ8BAf8EBAMC
AqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAhBgNVHREE
GjAYhwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBAQCH
23rXyP5vmFm060zquVTXKnBjwc1vuFzUd+/XVBzYfsRW0NDZvzILSf6bOkEaZq/Y
nSAR5oWSDsbbOPsqh/BziivAVL3dyj8dJmLqaUS2lko8cMB5rw0HcqGn4V7RjD68
y1A1AmZXG0Jo5Ulo2iXRrqF0CDMa2FNTAeTBsNhgZEXotkn8HMqASaaSSsO/+gTu
a1PrD71GYqD9FHmLhnY3GysmhLoX9gDJF7DWTpssEhEdHgp3fxz90vQ9s3UDvgb0
EipWe4+OzG31Ze0+Yyk1zkSc0ue0cDXqCpD/i4TOqhmv5PRl66i/Jj93UYotJ8cA
zPGYVRvDmAnP75bEyanI
-----END CERTIFICATE-----
---
Server certificate
subject=/O=testcorp
issuer=/O=testcorp
---
No client certificate CA names sent
Peer signing digest: SHA384
Server Temp Key: ECDH, P-256, 256 bits
---
SSL handshake has read 1389 bytes and written 266 bytes
---
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 5B4DB1A851ADFA7BBA98AC845905092F20DD89BB7C510B777760FF581F12DCF2
    Session-ID-ctx:
    Master-Key: 1AEB005E20921023757DA783A32FDA5C5AA5C9615ED07E6EF0B0A7EF0CD79F0531A84EE2AADC2B00AB5589B8C7BACE76
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket:
    0000 - bc ba f4 a0 0b 22 f9 68-bd 33 8a ac 57 6b a8 4f   .....".h.3..Wk.O
    0010 - 87 ae b2 47 f4 70 17 80-c5 bd 00 c7 7b c8 68 c3   ...G.p......{.h.
    0020 - 11 06 bc 52 eb 2f 38 d5-c4 7f 61 0f f9 34 a7 c5   ...R./8...a..4..
    0030 - 55 05 f0 f5 ef 42 9d 10-4e a4 dc 41 60 d1 c6 2c   U....B..N..A`..,
    0040 - 76 28 48 d3 fd 84 26 89-2e 34 4c 51 44 e0 86 c9   v(H...&..4LQD...
    0050 - c4 31 16 f6 db 34 ef c2-09 1b 45 ff 3c aa cb 9c   .1...4....E.<...
    0060 - 17 e7 53 0a 83 f9 fc 6e-cd 66 91 a5 d9 77 a9 0b   ..S....n.f...w..
    0070 - fa c2 0b 0c 69 a2 15 c9-                          ....i...

    Start Time: 1484688351
    Timeout   : 300 (sec)
    Verify return code: 10 (certificate has expired)
---
DONE
$
```

## Todo
### Best practices
I'm keen on any suggestions on low-hanging best practices I can implement. Feel free to send me a PR with any ideas you might have. Currently the timeouts are not adjustable, and are a simple first pass. I'm not sure what the most sensible defaults are, and whether they should be able to be tweaked, either directly or using a profile.

### Security Audit
This library is still in development (though I am anxious to see it to stability as soon as possible), but it could use an audit by someone who knows crypto better than me (which is probably pretty much anyone involved in crypto).  I'd especially be interested in whether or not the self-signed cert strategy is something I should even bother leaving in or not, but at the very least I'd like to make sure that the code I shamelessly cribbed from [generate_cert.go](https://golang.org/src/crypto/tls/generate_cert.go) is correct.


### Integration
I'm also curious as to whether or not I should try and at least provide a method to return a standard `net/http` server.  This would conceivably allow shttp to act as a convenient drop-in replacement for `net/http`, though it would also allow for accidental mucking about with the internals of the server and TLS configuration, and I would generally prefer to err on the side of caution when making an "easy" library for a hardened web server with crypto.

## Caveats
### STILL IN DEVELOPMENT
Seriously, it's not even stable; don't put it in production yet.

### Architectural Support
As mentioned in the article, at this time the the only architecture that supports [fast, optimized assembly versions](https://blog.cloudflare.com/go-crypto-bridging-the-performance-gap/) of the necessary crypto primitives is amd64, so this package will not compile on other architectures.  If and when such support becomes available, I will be sure to add it.

### Let's Encrypt
As of this first push, Let's Encrypt support is still being tested, and should be considered experimental. Of particular note are the concerns raised over rate limiting in the proposal mentioned above.

<sup>1</sup>See *Architectural Support* above
