package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Unix(1700000000, 0)

func nowFn() time.Time { return fixedNow }

func newReq(t testing.TB) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/items?id=7&x=y", strings.NewReader(`{"a":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Date", fixedNow.UTC().Format(http.TimeFormat))
	return r
}

var allComps = []string{"@method", "@target-uri", "@authority", "@scheme", "@request-target", "@path", "@query", `@query-param;name="id"`, "content-type", "date"}

func TestAllAlgorithmsRoundTrip(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	keys := loadKeys(t)
	hm := must(NewHMACSHA256("hmac", []byte("secret")))
	pairs := []struct {
		s Signer
		v Verifier
	}{
		{hm, hm},
		{must(NewEd25519Signer("ed", edPriv)), must(NewEd25519Verifier(edPub))},
		{must(NewECDSASigner("p256", p256)), must(NewECDSAVerifier(&p256.PublicKey))},
		{must(NewECDSASigner("p384", p384)), must(NewECDSAVerifier(&p384.PublicKey))},
		{must(NewRSAPSSSigner("pss", keys.pssPriv)), must(NewRSAPSSVerifier(keys.pssPub))},
		{must(NewRSAv15Signer("v15", keys.rsaPriv)), must(NewRSAv15Verifier(keys.rsaPub))},
	}
	for _, p := range pairs {
		t.Run(string(p.s.Algorithm()), func(t *testing.T) {
			if p.s.Algorithm() != p.v.Algorithm() {
				t.Fatal("alg mismatch")
			}
			r := newReq(t)
			err := Sign(r, "sig1", p.s, SignOptions{Components: allComps, Now: nowFn, IncludeAlg: true, ExpiresIn: time.Minute, Nonce: "n1", Tag: "app"})
			if err != nil {
				t.Fatal(err)
			}
			res, err := Verify(r, VerifyOptions{
				Resolver: StaticKeys{p.s.KeyID(): p.v}, Now: nowFn, MaxAge: time.Minute,
				RequiredComponents: []string{"@method", "@target-uri"}, AcceptedAlgorithms: []Algorithm{p.s.Algorithm()},
				RequireNonce: true, RequireExpires: true, Tag: "app",
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Algorithm != p.s.Algorithm() || res.Nonce != "n1" || res.Tag != "app" || res.KeyID != p.s.KeyID() ||
				!res.Created.Equal(fixedNow) || !res.Expires.Equal(fixedNow.Add(time.Minute)) || len(res.Components) != len(allComps) {
				t.Errorf("result %+v", res)
			}
			// Tamper: change a covered component.
			r.Header.Set("Content-Type", "text/plain")
			if _, err := Verify(r, VerifyOptions{Resolver: StaticKeys{p.s.KeyID(): p.v}, Now: nowFn}); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("tamper: %v", err)
			}
			// Bad signature length / garbage.
			r2 := newReq(t)
			_ = Sign(r2, "sig1", p.s, SignOptions{Components: []string{"@method"}, Now: nowFn})
			r2.Header.Set("Signature", "sig1=:AAAA:")
			if _, err := Verify(r2, VerifyOptions{Resolver: StaticKeys{p.s.KeyID(): p.v}, Now: nowFn}); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("garbage sig: %v", err)
			}
		})
	}
}

func TestKeyConstructorErrors(t *testing.T) {
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	checks := []error{
		second(NewHMACSHA256("k", nil)),
		second(NewEd25519Signer("k", ed25519.PrivateKey{1})),
		second(NewEd25519Verifier(ed25519.PublicKey{1})),
		second(NewECDSASigner("k", nil)),
		second(NewECDSAVerifier(nil)),
		second(NewECDSASigner("k", p224)),
		second(NewECDSAVerifier(&p224.PublicKey)),
		second(NewRSAPSSSigner("k", nil)),
		second(NewRSAPSSVerifier(nil)),
		second(NewRSAv15Signer("k", nil)),
		second(NewRSAv15Verifier(nil)),
	}
	for i, err := range checks {
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("check %d: %v", i, err)
		}
	}
}

func second[T any](_ T, err error) error { return err }

type failingSigner struct{ Signer }

func (failingSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("boom") }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestSignErrors(t *testing.T) {
	hm := must(NewHMACSHA256("k", []byte("s")))
	r := newReq(t)
	if err := Sign(r, "sig1", nil, SignOptions{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("nil signer: %v", err)
	}
	if err := Sign(r, "Bad Label", hm, SignOptions{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad label: %v", err)
	}
	if err := Sign(r, "sig1", hm, SignOptions{Components: []string{"@nope"}}); !errors.Is(err, ErrInvalidComponent) {
		t.Errorf("bad component: %v", err)
	}
	if err := Sign(r, "sig1", hm, SignOptions{Components: []string{"x-missing"}}); !errors.Is(err, ErrMissingComponent) {
		t.Errorf("missing: %v", err)
	}
	if err := Sign(r, "sig1", hm, SignOptions{Nonce: "\x01"}); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad nonce: %v", err)
	}
	if err := Sign(r, "sig1", failingSigner{hm}, SignOptions{}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("signer failure: %v", err)
	}
	if err := Sign(r, "sig1", hm, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(r, "sig1", hm, SignOptions{}); !errors.Is(err, ErrDuplicateLabel) {
		t.Errorf("dup: %v", err)
	}
	r.Header.Del("Signature-Input")
	if err := Sign(r, "sig1", hm, SignOptions{}); !errors.Is(err, ErrDuplicateLabel) {
		t.Errorf("dup sig: %v", err)
	}
	r.Header.Set("Signature-Input", "bad=(")
	if err := Sign(r, "sig2", hm, SignOptions{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("malformed existing input: %v", err)
	}
	r.Header.Del("Signature-Input")
	r.Header.Set("Signature", "bad=(")
	if err := Sign(r, "sig2", hm, SignOptions{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("malformed existing sig: %v", err)
	}
	// Randomized algorithms surface entropy failures.
	old := randReader
	randReader = errReader{}
	defer func() { randReader = old }()
	keys := loadKeys(t)
	for _, s := range []Signer{must(NewECDSASigner("e", keys.eccPriv)), must(NewRSAPSSSigner("p", keys.pssPriv))} {
		if err := Sign(newReq(t), "sig1", s, SignOptions{}); err == nil {
			t.Errorf("%s: expected entropy error", s.Algorithm())
		}
	}
	// Nil header map is initialised.
	bare := &http.Request{Method: "GET", URL: r.URL}
	randReader = old
	if err := Sign(bare, "sig1", hm, SignOptions{Components: []string{"@method"}}); err != nil || bare.Header.Get("Signature") == "" {
		t.Errorf("nil header: %v", err)
	}
}

func TestSignOptionsParams(t *testing.T) {
	hm := must(NewHMACSHA256("k", []byte("s")))
	r := newReq(t)
	err := Sign(r, "a", hm, SignOptions{OmitCreated: true, OmitKeyID: true, Expires: fixedNow.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Signature-Input"); got != "a=();expires=1700003600" {
		t.Errorf("got %s", got)
	}
	if err := Sign(r, "b", hm, SignOptions{KeyID: "other", Created: fixedNow}); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Signature-Input"); got != `a=();expires=1700003600, b=();created=1700000000;keyid="other"` {
		t.Errorf("got %s", got)
	}
	// created defaults to time.Now
	r2 := newReq(t)
	_ = Sign(r2, "c", hm, SignOptions{})
	res, err := Verify(r2, VerifyOptions{Resolver: StaticKeys{"k": hm}, MaxAge: time.Minute})
	if err != nil || time.Since(res.Created) > time.Minute {
		t.Errorf("default created: %v %v", res, err)
	}
}

func signed(t *testing.T, o SignOptions) (*http.Request, *HMAC) {
	t.Helper()
	hm := must(NewHMACSHA256("k", []byte("s")))
	r := newReq(t)
	if o.Now == nil {
		o.Now = nowFn
	}
	if err := Sign(r, "sig1", hm, o); err != nil {
		t.Fatal(err)
	}
	return r, hm
}

func TestVerifyPolicy(t *testing.T) {
	base := SignOptions{Components: []string{"@method", "@path"}}
	cases := []struct {
		name string
		sign SignOptions
		mod  func(r *http.Request, o *VerifyOptions)
		want error
	}{
		{"ok", base, nil, nil},
		{"no resolver", base, func(_ *http.Request, o *VerifyOptions) { o.Resolver = nil }, ErrUnknownKey},
		{"unknown key", base, func(_ *http.Request, o *VerifyOptions) { o.Resolver = StaticKeys{} }, ErrUnknownKey},
		{"resolver error", base, func(_ *http.Request, o *VerifyOptions) {
			o.Resolver = KeyResolverFunc(func(context.Context, string, Algorithm) (Verifier, error) { return nil, errors.New("db down") })
		}, ErrUnknownKey},
		{"resolver nil verifier", base, func(_ *http.Request, o *VerifyOptions) {
			o.Resolver = KeyResolverFunc(func(context.Context, string, Algorithm) (Verifier, error) { return nil, nil })
		}, ErrUnknownKey},
		{"no signature", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Del("Signature-Input") }, ErrNoSignature},
		{"no signature value", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Del("Signature") }, ErrNoSignature},
		{"wrong label", base, func(_ *http.Request, o *VerifyOptions) { o.Label = "other" }, ErrNoSignature},
		{"label ok", base, func(_ *http.Request, o *VerifyOptions) { o.Label = "sig1" }, nil},
		{"tag mismatch", SignOptions{Tag: "a"}, func(_ *http.Request, o *VerifyOptions) { o.Tag = "b" }, ErrPolicy},
		{"required component", base, func(_ *http.Request, o *VerifyOptions) { o.RequiredComponents = []string{"@authority"} }, ErrRequiredComponent},
		{"bad required component", base, func(_ *http.Request, o *VerifyOptions) { o.RequiredComponents = []string{"@bogus"} }, ErrInvalidComponent},
		{"require created", SignOptions{OmitCreated: true}, func(_ *http.Request, o *VerifyOptions) { o.RequireCreated = true }, ErrPolicy},
		{"maxage implies created", SignOptions{OmitCreated: true}, func(_ *http.Request, o *VerifyOptions) { o.MaxAge = time.Second }, ErrPolicy},
		{"require expires", base, func(_ *http.Request, o *VerifyOptions) { o.RequireExpires = true }, ErrPolicy},
		{"require nonce", base, func(_ *http.Request, o *VerifyOptions) { o.RequireNonce = true }, ErrPolicy},
		{"nonce checker", SignOptions{Nonce: "abc"}, func(_ *http.Request, o *VerifyOptions) {
			o.NonceChecker = func(_ context.Context, n string) error {
				if n == "abc" {
					return errors.New("replayed")
				}
				return nil
			}
		}, ErrPolicy},
		{"future", base, func(_ *http.Request, o *VerifyOptions) {
			o.Now = func() time.Time { return fixedNow.Add(-time.Minute) }
		}, ErrNotYetValid},
		{"future within skew", base, func(_ *http.Request, o *VerifyOptions) {
			o.Now = func() time.Time { return fixedNow.Add(-time.Second) }
			o.ClockSkew = 5 * time.Second
		}, nil},
		{"expired", SignOptions{ExpiresIn: time.Second}, func(_ *http.Request, o *VerifyOptions) { o.Now = func() time.Time { return fixedNow.Add(time.Minute) } }, ErrExpired},
		{"expired within skew", SignOptions{ExpiresIn: time.Second}, func(_ *http.Request, o *VerifyOptions) {
			o.Now = func() time.Time { return fixedNow.Add(3 * time.Second) }
			o.ClockSkew = 5 * time.Second
		}, nil},
		{"max age", base, func(_ *http.Request, o *VerifyOptions) {
			o.MaxAge = time.Minute
			o.Now = func() time.Time { return fixedNow.Add(2 * time.Minute) }
		}, ErrExpired},
		{"alg param not accepted", SignOptions{IncludeAlg: true}, func(_ *http.Request, o *VerifyOptions) { o.AcceptedAlgorithms = []Algorithm{AlgEd25519} }, ErrAlgorithm},
		{"key alg not accepted", base, func(_ *http.Request, o *VerifyOptions) { o.AcceptedAlgorithms = []Algorithm{AlgEd25519} }, ErrAlgorithm},
		{"alg mismatch", SignOptions{IncludeAlg: true}, func(_ *http.Request, o *VerifyOptions) {
			_, pub := ed25519Pair()
			o.Resolver = StaticKeys{"k": pub}
		}, ErrAlgorithm},
		{"key mismatch", base, func(_ *http.Request, o *VerifyOptions) {
			o.Resolver = StaticKeys{"k": must(NewHMACSHA256("k", []byte("other")))}
		}, ErrInvalidSignature},
		{"malformed input", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature-Input", "sig1=(") }, ErrMalformed},
		{"malformed sig field", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature", "sig1=(") }, ErrMalformed},
		{"input not inner list", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature-Input", "sig1=1") }, ErrMalformed},
		{"sig is inner list", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature", "sig1=(1)") }, ErrMalformed},
		{"sig not bytes", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature", "sig1=1") }, ErrMalformed},
		{"bad created type", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature-Input", `sig1=();created="x"`) }, ErrMalformed},
		{"bad keyid type", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature-Input", `sig1=();keyid=1`) }, ErrMalformed},
		{"bad component item", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature-Input", `sig1=(1);keyid="k"`) }, ErrInvalidComponent},
		{"uppercase component", base, func(r *http.Request, _ *VerifyOptions) { r.Header.Set("Signature-Input", `sig1=("Date");keyid="k"`) }, ErrInvalidComponent},
		{"missing covered field", base, func(r *http.Request, _ *VerifyOptions) {
			r.Header.Set("Signature-Input", `sig1=("x-gone");keyid="k"`)
		}, ErrMissingComponent},
		{"unknown params ignored", base, func(r *http.Request, _ *VerifyOptions) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `keyid="k"`, `keyid="k";foo=bar`, 1))
		}, ErrInvalidSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, hm := signed(t, c.sign)
			o := VerifyOptions{Resolver: StaticKeys{"k": hm}, Now: nowFn}
			if c.mod != nil {
				c.mod(r, &o)
			}
			_, err := Verify(r, o)
			if c.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

type plainErrVerifier struct{}

func (plainErrVerifier) Algorithm() Algorithm     { return AlgHMACSHA256 }
func (plainErrVerifier) Verify(_, _ []byte) error { return errors.New("nope") }

func TestVerifierPlainErrorWrapped(t *testing.T) {
	r, _ := signed(t, SignOptions{})
	_, err := Verify(r, VerifyOptions{Resolver: StaticKeys{"k": plainErrVerifier{}}, Now: nowFn})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatal(err)
	}
}

func ed25519Pair() (Signer, Verifier) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return must(NewEd25519Signer("ed", priv)), must(NewEd25519Verifier(pub))
}

func TestMultipleSignatures(t *testing.T) {
	hm := must(NewHMACSHA256("k", []byte("s")))
	es, ev := ed25519Pair()
	r := newReq(t)
	if err := Sign(r, "first", hm, SignOptions{Components: []string{"@method"}, Now: nowFn, Tag: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(r, "second", es, SignOptions{Components: []string{"@method", "@path"}, Now: nowFn, Tag: "b"}); err != nil {
		t.Fatal(err)
	}
	keys := StaticKeys{"k": hm, "ed": ev}
	res, err := Verify(r, VerifyOptions{Resolver: keys, Now: nowFn, Tag: "b"})
	if err != nil || res.Label != "second" {
		t.Fatalf("%v %v", res, err)
	}
	// first fails (key unknown) but second succeeds.
	res, err = Verify(r, VerifyOptions{Resolver: StaticKeys{"ed": ev}, Now: nowFn})
	if err != nil || res.Label != "second" {
		t.Fatalf("%v %v", res, err)
	}
	// both fail -> first error returned
	_, err = Verify(r, VerifyOptions{Resolver: StaticKeys{}, Now: nowFn})
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatal(err)
	}
	// Labelled failure returns that error.
	_, err = Verify(r, VerifyOptions{Resolver: StaticKeys{}, Now: nowFn, Label: "second"})
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatal(err)
	}
}

func TestResponseSignVerify(t *testing.T) {
	es, ev := ed25519Pair()
	req := newReq(t)
	resp := &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": {"application/json"}}, Request: req, Body: io.NopCloser(strings.NewReader("{}"))}
	opts := SignOptions{Components: []string{"@status", "content-type", "@method;req", "@target-uri;req", "content-type;req"}, Now: nowFn}
	if err := SignResponse(resp, "res", es, opts); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyResponse(resp, VerifyOptions{Resolver: StaticKeys{"ed": ev}, Now: nowFn, RequiredComponents: []string{"@status", "@method;req"}})
	if err != nil || !res.Covers("@target-uri;req") || res.Covers("@bogus") {
		t.Fatalf("%v %v", res, err)
	}
	// A response to a different request fails.
	other := newReq(t)
	other.Method = http.MethodPut
	resp.Request = other
	if _, err := VerifyResponse(resp, VerifyOptions{Resolver: StaticKeys{"ed": ev}, Now: nowFn}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatal(err)
	}
	// Nil header and no request.
	bare := &http.Response{StatusCode: 204}
	if err := SignResponse(bare, "res", es, SignOptions{Components: []string{"@status"}, Now: nowFn}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResponse(bare, VerifyOptions{Resolver: StaticKeys{"ed": ev}, Now: nowFn}); err != nil {
		t.Fatal(err)
	}
}

func TestStructuredFieldOption(t *testing.T) {
	hm := must(NewHMACSHA256("k", []byte("s")))
	r := newReq(t)
	r.Header.Set("Example-Dict", "a=1,    b=2")
	ft := map[string]FieldType{"example-dict": FieldDictionary}
	if err := Sign(r, "s", hm, SignOptions{Components: []string{"example-dict;sf", `example-dict;key="b"`}, FieldTypes: ft, Now: nowFn}); err != nil {
		t.Fatal(err)
	}
	// Whitespace changes by an intermediary do not break ;sf signatures.
	r.Header.Set("Example-Dict", "a=1, b=2")
	if _, err := Verify(r, VerifyOptions{Resolver: StaticKeys{"k": hm}, FieldTypes: ft, Now: nowFn}); err != nil {
		t.Fatal(err)
	}
	// Without the type the verifier cannot reproduce the base.
	if _, err := Verify(r, VerifyOptions{Resolver: StaticKeys{"k": hm}, Now: nowFn}); !errors.Is(err, ErrInvalidComponent) {
		t.Fatal(err)
	}
}
