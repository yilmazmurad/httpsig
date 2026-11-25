package httpsig

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestContentDigest(t *testing.T) {
	// RFC 9530 example: {"hello": "world"}
	d, err := ContentDigest(DigestSHA512, []byte(`{"hello": "world"}`))
	if err != nil || d != "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:" {
		t.Fatalf("%s %v", d, err)
	}
	d256, _ := ContentDigest(DigestSHA256, []byte(`{"hello": "world"}`))
	if d256 != "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:" {
		t.Fatal(d256)
	}
	if err := VerifyContentDigest(d+", "+d256+", md5=:AAA=:", []byte(`{"hello": "world"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ContentDigest("md5", nil); !errors.Is(err, ErrContentDigest) {
		t.Fatal(err)
	}
	for _, bad := range []string{d + ", sha-256=:AAAA:", "md5=:AAA=:", "sha-256=(1)", "sha-256=1", "(", ""} {
		if err := VerifyContentDigest(bad, []byte(`{"hello": "world"}`)); !errors.Is(err, ErrContentDigest) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

type testSetup struct {
	signer Signer
	keys   StaticKeys
}

func newSetup() testSetup {
	s, v := ed25519Pair()
	return testSetup{signer: s, keys: StaticKeys{"ed": v}}
}

func TestTransportAndMiddlewareEndToEnd(t *testing.T) {
	ts := newSetup()
	var got *Result
	var gotBody string
	h := Middleware(MiddlewareConfig{
		Verify: VerifyOptions{
			Resolver: ts.keys, MaxAge: time.Minute,
			RequiredComponents: []string{"@method", "@authority", "@path", "@query", "content-digest", "content-length", "content-type"},
		},
		VerifyContentDigest: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = ResultFromContext(r.Context())
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	client := &http.Client{Transport: &Transport{
		Signer:        ts.signer,
		ContentDigest: DigestSHA256,
		Options: SignOptions{Components: []string{"@method", "@authority", "@path", "@query", "@target-uri",
			"@request-target", "@scheme", "content-digest", "content-length", "content-type", "host"}},
	}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/orders?id=42", strings.NewReader(`{"qty":3}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got == nil || got.Label != "sig1" || gotBody != `{"qty":3}` {
		t.Fatalf("result %+v body %q", got, gotBody)
	}
	if req.Header.Get("Signature") != "" {
		t.Fatal("transport mutated the caller's request")
	}

	// GET without body and without digest.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/x?id=1", nil)
	tr := &Transport{Signer: ts.signer, Label: "c", Options: SignOptions{Components: []string{"@method", "@authority", "@path", "@query"}}}
	resp, err = (&http.Client{Transport: tr}).Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized { // content-digest etc. required by policy
		t.Fatalf("status %d", resp.StatusCode)
	}

	// Unsigned request.
	resp, err = http.Post(srv.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(b), "signature required") {
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
}

func TestMiddlewareDigestFailures(t *testing.T) {
	ts := newSetup()
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mw := Middleware(MiddlewareConfig{Verify: VerifyOptions{Resolver: ts.keys}, VerifyContentDigest: true, MaxBodyBytes: 8})
	do := func(body string, digest string, comps []string) int {
		r := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(body))
		if body == "" {
			r = httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		}
		if digest != "" {
			r.Header.Set("Content-Digest", digest)
		}
		if err := Sign(r, "s", ts.signer, SignOptions{Components: comps}); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		mw(ok).ServeHTTP(w, r)
		return w.Code
	}
	good, _ := ContentDigest(DigestSHA256, []byte("abc"))
	cd := []string{"@method", "content-digest"}
	if c := do("abc", good, cd); c != 200 {
		t.Errorf("good: %d", c)
	}
	if c := do("", "", []string{"@method"}); c != 200 {
		t.Errorf("no body: %d", c)
	}
	if c := do("abc", "", []string{"@method"}); c != 400 {
		t.Errorf("missing digest: %d", c)
	}
	if c := do("abc", good, []string{"@method"}); c != 400 {
		t.Errorf("uncovered digest: %d", c)
	}
	if c := do("abd", good, cd); c != 400 {
		t.Errorf("wrong digest: %d", c)
	}
	big, _ := ContentDigest(DigestSHA256, []byte("0123456789"))
	if c := do("0123456789", big, cd); c != 400 {
		t.Errorf("too big: %d", c)
	}
	// Body read error.
	r := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	r.Body = io.NopCloser(errBody{})
	r.ContentLength = 5
	r.Header.Set("Content-Digest", good)
	_ = Sign(r, "s", ts.signer, SignOptions{Components: cd})
	w := httptest.NewRecorder()
	mw(ok).ServeHTTP(w, r)
	if w.Code != 400 {
		t.Errorf("read error: %d", w.Code)
	}
	// Malformed fields -> 400 by default; custom error handler.
	r = httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.Header.Set("Signature-Input", "s=(")
	w = httptest.NewRecorder()
	mw(ok).ServeHTTP(w, r)
	if w.Code != 400 {
		t.Errorf("malformed: %d", w.Code)
	}
	called := false
	custom := Middleware(MiddlewareConfig{Verify: VerifyOptions{Resolver: ts.keys}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
		called = errors.Is(err, ErrNoSignature)
		w.WriteHeader(http.StatusForbidden)
	}})
	w = httptest.NewRecorder()
	custom(ok).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || w.Code != http.StatusForbidden {
		t.Errorf("custom handler: %v %d", called, w.Code)
	}
	if _, ok := ResultFromContext(r.Context()); ok {
		t.Error("unexpected result in context")
	}
}

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

func TestTransportErrors(t *testing.T) {
	ts := newSetup()
	body := &closeTracker{Reader: strings.NewReader("x")}
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", body)
	if _, err := (&Transport{}).RoundTrip(req); err == nil || !body.closed {
		t.Errorf("nil signer: %v closed=%v", err, body.closed)
	}
	body = &closeTracker{Reader: strings.NewReader("x")}
	req, _ = http.NewRequest(http.MethodPost, "http://example.com/", body)
	if _, err := (&Transport{Signer: ts.signer, Options: SignOptions{Components: []string{"x-missing"}}}).RoundTrip(req); !errors.Is(err, ErrMissingComponent) || !body.closed {
		t.Errorf("sign error: %v closed=%v", err, body.closed)
	}
	body = &closeTracker{Reader: strings.NewReader("x")}
	req, _ = http.NewRequest(http.MethodPost, "http://example.com/", body)
	if _, err := (&Transport{Signer: ts.signer, ContentDigest: "md5"}).RoundTrip(req); !errors.Is(err, ErrContentDigest) || !body.closed {
		t.Errorf("digest alg error: %v closed=%v", err, body.closed)
	}
	req, _ = http.NewRequest(http.MethodPost, "http://example.com/", io.NopCloser(errBody{}))
	if _, err := (&Transport{Signer: ts.signer, ContentDigest: DigestSHA256}).RoundTrip(req); err == nil {
		t.Error("expected body read error")
	}
	// Base transport is used; GetBody works; empty body gets a digest too.
	var seen *http.Request
	base := rtFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
	})
	req, _ = http.NewRequest(http.MethodPost, "http://example.com/", bytes.NewReader([]byte("hello")))
	tr := &Transport{Base: base, Signer: ts.signer, ContentDigest: DigestSHA512, Options: SignOptions{Components: []string{"content-digest"}}}
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	rc, _ := seen.GetBody()
	b, _ := io.ReadAll(rc)
	if string(b) != "hello" || seen.ContentLength != 5 || seen.Header.Get("Content-Digest") == "" {
		t.Errorf("body %q len %d", b, seen.ContentLength)
	}
	if _, err := Verify(seen, VerifyOptions{Resolver: ts.keys}); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if _, err := tr.RoundTrip(req); err != nil || seen.Header.Get("Content-Digest") == "" {
		t.Fatalf("empty body digest: %v", err)
	}
}

func TestResponseSignerMiddleware(t *testing.T) {
	ts := newSetup()
	opts := SignOptions{Components: []string{"@status", "content-type", "@method;req", "@path;req"}}
	handler := ResponseSigner("resp", ts.signer, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		switch r.URL.Path {
		case "/created":
			w.WriteHeader(http.StatusCreated)
			w.WriteHeader(http.StatusOK) // ignored
			io.WriteString(w, "made")
		case "/implicit":
			io.WriteString(w, "hello")
		case "/empty":
		case "/bad":
			w.Header().Del("Content-Type")
			io.WriteString(w, "nope")
		}
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()
	for path, wantCode := range map[string]int{"/created": 201, "/implicit": 200, "/empty": 200, "/bad": 500} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != wantCode {
			t.Errorf("%s: status %d", path, resp.StatusCode)
			continue
		}
		if wantCode == 500 {
			if resp.Header.Get("Signature") != "" {
				t.Errorf("%s: unexpected signature", path)
			}
			continue
		}
		res, err := VerifyResponse(resp, VerifyOptions{Resolver: ts.keys, RequiredComponents: []string{"@status", "@path;req"}})
		if err != nil || res.Label != "resp" {
			t.Errorf("%s: %v", path, err)
		}
	}
	// Unwrap supports ResponseController.
	sw := &signingWriter{ResponseWriter: httptest.NewRecorder()}
	if sw.Unwrap() == nil {
		t.Error("unwrap")
	}
}

func TestSignResponseHeader(t *testing.T) {
	ts := newSetup()
	req := newReq(t)
	h := http.Header{"Content-Type": {"application/json"}}
	if err := SignResponseHeader(h, 200, req, "r", ts.signer, SignOptions{Components: []string{"@status", "content-type", "@authority;req"}}); err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{StatusCode: 200, Header: h, Request: req}
	if _, err := VerifyResponse(resp, VerifyOptions{Resolver: ts.keys}); err != nil {
		t.Fatal(err)
	}
}
