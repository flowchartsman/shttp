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
	"net/http"

	"github.com/alaska/shttp"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "You've accessed %s", r.URL.Path[1:])
}

func main() {
	s, err := shttp.NewServerWithRedirect("", shttp.SelfCert("testcorp", ""))
	if err != nil {
		panic(err.Error())
	}
	http.HandleFunc("/", handler)
	if err := s.ListenAndServeTLS(); err != nil {
		panic(err.Error())
	}
}
```

```
$ curl -k https://localhost/stuff
You've accessed stuff
$ curl -k http://localhost/stuff
<a href="https://127.0.0.1/stuff">Moved Permanently</a>.
$ curl -kL http://localhost/stuff
You've accessed stuff
$
```

## Todo
### Audit
Currently this library is in beta, though I am anxious to see it to stability as soon as possible, but it could use an audit by someone who knows crypto better than me (which is probably pretty much anyone involved in crypto).  I'd especially be interested in whether or not the self-signed cert strategy is something I should even bother leaving in or not, but at the very least I'd like to make sure that the code I shamelessly cribbed from [generate_cert.go](https://golang.org/src/crypto/tls/generate_cert.go) is correct.

I'd also be interested in any suggestions on low-hanging best practices I can implement. Feel free to send me a PR with any ideas you might have. Currently the timeouts are not adjustable, but perhaps they should be. Any further options would probably see me adopting the functional `...optionFunc` approach.

### Feedback
I'm also curious as to whether or not I should try and at least provide a method to return a standard `net/http` server.  This would conceivably allow shttp to act as a convenient drop-in replacement for `net/http`, though it would also allow for accidental mucking about with the internals of the server and TLS configuration, and I would generally prefer to err on the side of caution when making an "easy" library for a hardened web server with crypto.

## Caveats
### STILL BETA
### Architectural Support
As mentioned in the article, at this time the the only architecture that supports [fast, optimized assembly versions](https://blog.cloudflare.com/go-crypto-bridging-the-performance-gap/) of the necessary crypto primitives is amd64, so this package will not compile on other architectures.  If and when such support becomes available, I will be sure to add it.

### Let's Encrypt
As of this first push, Let's Encrypt support is still being tested, and should be considered experimental. Of particular note are the concerns raised over rate limiting in the proposal mentioned above.

<sup>1</sup>See *Architectural Support* above
