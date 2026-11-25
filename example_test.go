package httpsig_test

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/yilmazmurad/httpsig"
)

func ExampleSign() {
	signer, _ := httpsig.NewHMACSHA256("my-key", []byte("shared secret"))

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/orders?id=42", strings.NewReader(`{"qty":3}`))
	req.Header.Set("Content-Type", "application/json")

	err := httpsig.Sign(req, "sig1", signer, httpsig.SignOptions{
		Components: []string{"@method", "@authority", "@path", `@query-param;name="id"`, "content-type"},
		Created:    time.Unix(1700000000, 0),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(req.Header.Get("Signature-Input"))
	fmt.Println(req.Header.Get("Signature"))
	// Output:
	// sig1=("@method" "@authority" "@path" "@query-param";name="id" "content-type");created=1700000000;keyid="my-key"
	// sig1=:Hpat+FouXC/z5Piq5FzuY/CkZls4/ndWTAu5wdAlajI=:
}

func ExampleVerify() {
	key, _ := httpsig.NewHMACSHA256("my-key", []byte("shared secret"))

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/items", nil)
	_ = httpsig.Sign(req, "sig1", key, httpsig.SignOptions{
		Components: []string{"@method", "@authority", "@path"},
	})

	res, err := httpsig.Verify(req, httpsig.VerifyOptions{
		Resolver:           httpsig.StaticKeys{"my-key": key},
		RequiredComponents: []string{"@method", "@path"},
		MaxAge:             5 * time.Minute,
		AcceptedAlgorithms: []httpsig.Algorithm{httpsig.AlgHMACSHA256},
	})
	if err != nil {
		fmt.Println("rejected:", err)
		return
	}
	fmt.Println(res.Label, res.KeyID, res.Algorithm, res.Components)
	// Output: sig1 my-key hmac-sha256 ["@method" "@authority" "@path"]
}

func ExampleMiddleware() {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := httpsig.NewEd25519Signer("client-1", priv)
	verifier, _ := httpsig.NewEd25519Verifier(pub)

	protected := httpsig.Middleware(httpsig.MiddlewareConfig{
		Verify: httpsig.VerifyOptions{
			Resolver:           httpsig.StaticKeys{"client-1": verifier},
			RequiredComponents: []string{"@method", "@authority", "@path", "content-digest"},
			MaxAge:             time.Minute,
		},
		VerifyContentDigest: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, _ := httpsig.ResultFromContext(r.Context())
		fmt.Fprintf(w, "hello %s", res.KeyID)
	}))
	srv := httptest.NewServer(protected)
	defer srv.Close()

	client := &http.Client{Transport: &httpsig.Transport{
		Signer:        signer,
		ContentDigest: httpsig.DigestSHA256,
		Options: httpsig.SignOptions{
			Components: []string{"@method", "@authority", "@path", "content-digest"},
		},
	}}
	resp, err := client.Post(srv.URL+"/hook", "application/json", strings.NewReader(`{"event":"ping"}`))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.StatusCode, string(body))

	unsigned, err := http.Post(srv.URL+"/hook", "application/json", strings.NewReader(`{}`))
	if err != nil {
		panic(err)
	}
	unsigned.Body.Close()
	fmt.Println(unsigned.StatusCode)
	// Output:
	// 200 hello client-1
	// 401
}

func ExampleSignResponseHeader() {
	key, _ := httpsig.NewHMACSHA256("server", []byte("secret"))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		err := httpsig.SignResponseHeader(w.Header(), http.StatusOK, r, "res", key, httpsig.SignOptions{
			Components: []string{"@status", "content-type", "@method;req", "@path;req"},
			Created:    time.Unix(1700000000, 0),
		})
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		io.WriteString(w, "ok")
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	fmt.Println(rec.Header().Get("Signature-Input"))

	// The client verifies the response against its own request.
	resp := rec.Result()
	resp.Request = httptest.NewRequest(http.MethodGet, "/status", nil)
	_, err := httpsig.VerifyResponse(resp, httpsig.VerifyOptions{
		Resolver: httpsig.StaticKeys{"server": key},
		Now:      func() time.Time { return time.Unix(1700000010, 0) },
	})
	fmt.Println("verified:", err == nil)
	// Output:
	// res=("@status" "content-type" "@method";req "@path";req);created=1700000000;keyid="server"
	// verified: true
}

func ExampleTransport() {
	signer, _ := httpsig.NewHMACSHA256("k1", []byte("secret"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Header.Get("Signature-Input") != "")
	}))
	defer srv.Close()

	client := &http.Client{Transport: &httpsig.Transport{
		Signer:  signer,
		Label:   "client",
		Options: httpsig.SignOptions{Components: []string{"@method", "@target-uri"}, ExpiresIn: time.Minute},
	}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println("signed:", string(b))
	// Output: signed: true
}
