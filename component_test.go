package httpsig

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func compValue(t *testing.T, msg message, id string, ft map[string]FieldType) (string, error) {
	t.Helper()
	c, err := ParseComponent(id)
	if err != nil {
		return "", err
	}
	r := &resolver{msg: msg, fieldTypes: ft}
	return r.value(c)
}

// Examples from RFC 9421 §2.1.
func TestHTTPFieldExamples(t *testing.T) {
	req := readRequest(t, "GET / HTTP/1.1\r\n"+
		"Host: www.example.com\r\n"+
		"Date: Tue, 20 Apr 2021 02:07:56 GMT\r\n"+
		"X-OWS-Header:   Leading and trailing whitespace.   \r\n"+
		"Cache-Control: max-age=60\r\n"+
		"Cache-Control:    must-revalidate\r\n"+
		"Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)\r\n"+
		"X-Empty-Header: \r\n"+
		"Example-Header: value, with, lots\r\n"+
		"Example-Header: of, commas\r\n"+
		"Single-Header: value, with, lots, of, commas\r\n"+
		"\r\n")
	// Simulate obsolete line folding as it may appear in a raw header map.
	req.Header["X-Obs-Fold-Header"] = []string{"Obsolete\r\n    line folding."}
	req.Header["Example-Dict2"] = []string{"a=1, b=2;x=1;y=2, c=(a   b    c), d"}
	msg := message{req: req}
	ft := map[string]FieldType{"example-dict": FieldDictionary}
	cases := []struct{ id, want string }{
		{"host", "www.example.com"},
		{"date", "Tue, 20 Apr 2021 02:07:56 GMT"},
		{"x-ows-header", "Leading and trailing whitespace."},
		{"x-obs-fold-header", "Obsolete line folding."},
		{"cache-control", "max-age=60, must-revalidate"},
		{"example-dict", "a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
		{"x-empty-header", ""},
		{"example-dict;sf", "a=1, b=2;x=1;y=2, c=(a b c)"},
		{`example-dict2;key="a"`, "1"},
		{`example-dict2;key="d"`, "?1"},
		{`example-dict2;key="b"`, "2;x=1;y=2"},
		{`example-dict2;key="c"`, "(a b c)"},
		{"example-header", "value, with, lots, of, commas"},
		{"example-header;bs", ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:"},
		{"single-header;bs", ":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:"},
	}
	for _, c := range cases {
		got, err := compValue(t, msg, c.id, ft)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q (%v), want %q", c.id, got, err, c.want)
		}
	}
	errCases := map[string]error{
		"missing-header":         ErrMissingComponent,
		`example-dict2;key="zz"`: ErrMissingComponent,
		`cache-control;key="a"`:  nil, // max-age=60 parses as a dictionary... must-revalidate too
		"x-ows-header;sf":        ErrInvalidComponent,
		`date;key="a"`:           ErrMissingComponent,
		"example-dict;bs;sf":     ErrInvalidComponent,
		"content-type;req":       ErrInvalidComponent,
		"date;tr":                ErrMissingComponent,
		"date;foo":               ErrInvalidComponent,
		"date;sf=1":              ErrInvalidComponent,
		`date;key=1`:             ErrInvalidComponent,
		`date;name="x"`:          ErrInvalidComponent,
		"date;req=?0":            ErrInvalidComponent,
		`"Date"`:                 ErrInvalidComponent,
		`"date`:                  ErrInvalidComponent,
		`""`:                     ErrInvalidComponent,
		`x;;`:                    ErrInvalidComponent,
	}
	for id, want := range errCases {
		_, err := compValue(t, msg, id, ft)
		if want == nil {
			if err == nil || !errors.Is(err, ErrMissingComponent) {
				// cache-control "a" key is absent -> missing
				t.Errorf("%s: got %v", id, err)
			}
			continue
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", id, err, want)
		}
	}
	// sf on invalid structured value
	req.Header.Set("Bad-Dict", "a=(")
	for _, id := range []string{"bad-dict;sf", `bad-dict;key="a"`} {
		if _, err := compValue(t, msg, id, map[string]FieldType{"bad-dict": FieldDictionary}); !errors.Is(err, ErrMissingComponent) {
			t.Errorf("%s: %v", id, err)
		}
	}
	req.Header.Set("List-H", "a,   b;x")
	req.Header.Set("Item-H", `  "x";y=1  `)
	for id, want := range map[string]string{"list-h;sf": "a, b;x", "item-h;sf": `"x";y=1`} {
		got, err := compValue(t, msg, id, map[string]FieldType{"list-h": FieldList, "item-h": FieldItem})
		if err != nil || got != want {
			t.Errorf("%s: %q %v", id, got, err)
		}
	}
	for _, id := range []string{"list-h;sf", "item-h;sf"} {
		req.Header.Set("List-H", "a,")
		req.Header.Set("Item-H", "a b")
		if _, err := compValue(t, msg, id, map[string]FieldType{"list-h": FieldList, "item-h": FieldItem}); !errors.Is(err, ErrMissingComponent) {
			t.Errorf("%s: %v", id, err)
		}
	}
	// Known registered type without FieldTypes.
	req.Header.Set("Content-Digest", "sha-256=:AAA=:,   sha-512=:AAA=:")
	if got, err := compValue(t, msg, "content-digest;sf", nil); err != nil || got != "sha-256=:AAA=:, sha-512=:AAA=:" {
		t.Errorf("content-digest;sf: %q %v", got, err)
	}
	// Non-canonical header map key.
	req.Header["x-lower"] = []string{"v"}
	if got, err := compValue(t, msg, "x-lower", nil); err != nil || got != "v" {
		t.Errorf("x-lower: %q %v", got, err)
	}
}

// Examples from RFC 9421 §2.2.
func TestDerivedComponents(t *testing.T) {
	req := readRequest(t, "POST /path?param=value HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
	req.TLS = &tls.ConnectionState{}
	msg := message{req: req}
	cases := map[string]string{
		"@method":         "POST",
		"@target-uri":     "https://www.example.com/path?param=value",
		"@authority":      "www.example.com",
		"@scheme":         "https",
		"@request-target": "/path?param=value",
		"@path":           "/path",
		"@query":          "?param=value",
	}
	for id, want := range cases {
		got, err := compValue(t, msg, id, nil)
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v), want %q", id, got, err, want)
		}
	}
	req.TLS = nil
	if got, _ := compValue(t, msg, "@scheme", nil); got != "http" {
		t.Errorf("@scheme plain: %q", got)
	}

	// Query parameters (§2.2.8).
	q := readRequest(t, "GET /parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something&qux=&dup=1&dup=2&&bad=%zz HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
	qm := message{req: q}
	qcases := map[string]string{
		`@query-param;name="var"`:                  "this%20is%20a%20big%0Amultiline%20value",
		`@query-param;name="bar"`:                  "with%20plus%20whitespace",
		`@query-param;name="fa%C3%A7ade%22%3A%20"`: "something",
		`@query-param;name="qux"`:                  "",
		`@query-param;name="bad"`:                  "%25zz",
	}
	for id, want := range qcases {
		got, err := compValue(t, qm, id, nil)
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v), want %q", id, got, err, want)
		}
	}
	for _, id := range []string{`@query-param;name="dup"`, `@query-param;name="nope"`} {
		if _, err := compValue(t, qm, id, nil); !errors.Is(err, ErrMissingComponent) {
			t.Errorf("%s: %v", id, err)
		}
	}

	// Defaults and edge cases using client-side requests.
	u, _ := url.Parse("HTTP://Example.COM:80")
	cr := &http.Request{URL: u, Header: http.Header{}}
	cm := message{req: cr}
	edge := map[string]string{
		"@method":         "GET",
		"@path":           "/",
		"@query":          "?",
		"@authority":      "example.com",
		"@scheme":         "http",
		"@target-uri":     "http://example.com/",
		"@request-target": "/",
	}
	for id, want := range edge {
		got, err := compValue(t, cm, id, nil)
		if err != nil || got != want {
			t.Errorf("edge %s: got %q (%v), want %q", id, got, err, want)
		}
	}
	u6, _ := url.Parse("https://[::1]:443/x?y")
	if got, _ := compValue(t, message{req: &http.Request{URL: u6}}, "@authority", nil); got != "[::1]" {
		t.Errorf("ipv6 authority: %q", got)
	}
	u8, _ := url.Parse("https://h:8443/x")
	if got, _ := compValue(t, message{req: &http.Request{URL: u8}}, "@authority", nil); got != "h:8443" {
		t.Errorf("port authority: %q", got)
	}
	conn := &http.Request{Method: http.MethodConnect, Host: "www.example.com:80", URL: &url.URL{Host: "www.example.com:80"}}
	if got, _ := compValue(t, message{req: conn}, "@request-target", nil); got != "www.example.com:80" {
		t.Errorf("connect: %q", got)
	}
	conn2 := &http.Request{Method: http.MethodConnect, Host: "h:8080"}
	if got, _ := compValue(t, message{req: conn2}, "@request-target", nil); got != "h:8080" {
		t.Errorf("connect host: %q", got)
	}
	noURL := &http.Request{}
	for _, id := range []string{"@path", "@query", "@authority", "@target-uri"} {
		got, err := compValue(t, message{req: noURL}, id, nil)
		switch id {
		case "@path":
			if got != "/" {
				t.Errorf("nil URL %s = %q", id, got)
			}
		case "@query":
			if got != "?" {
				t.Errorf("nil URL %s = %q", id, got)
			}
		default:
			if !errors.Is(err, ErrMissingComponent) {
				t.Errorf("nil URL %s: %v", id, err)
			}
		}
	}
	// Host fallback via URL.Host and content-length fallback.
	ch := &http.Request{URL: &url.URL{Scheme: "https", Host: "api.example"}, Header: http.Header{}, ContentLength: 42}
	if got, _ := compValue(t, message{req: ch}, "host", nil); got != "api.example" {
		t.Errorf("host fallback %q", got)
	}
	if got, _ := compValue(t, message{req: ch}, "content-length", nil); got != "42" {
		t.Errorf("content-length fallback %q", got)
	}

	// Invalid derived components.
	for id, want := range map[string]error{
		"@unknown":          ErrInvalidComponent,
		"@signature-params": ErrInvalidComponent,
		"@query-param":      ErrInvalidComponent,
		"@method;sf":        ErrInvalidComponent,
		`@method;key="a"`:   ErrInvalidComponent,
		"@status":           ErrInvalidComponent,
		"@method;req":       ErrInvalidComponent,
	} {
		if _, err := compValue(t, msg, id, nil); !errors.Is(err, want) {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestResponseComponents(t *testing.T) {
	req := readRequest(t, testRequest)
	resp := &responseParts{status: 200, header: http.Header{"Content-Type": {"text/plain"}}, trailer: http.Header{"Expires": {"Wed, 9 Nov 2022 07:28:00 GMT"}}}
	msg := message{req: req, resp: resp}
	cases := map[string]string{
		"@status":          "200",
		"content-type":     "text/plain",
		"content-type;req": "application/json",
		"@method;req":      "POST",
		"expires;tr":       "Wed, 9 Nov 2022 07:28:00 GMT",
		"host;req":         "example.com",
	}
	for id, want := range cases {
		got, err := compValue(t, msg, id, nil)
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v), want %q", id, got, err, want)
		}
	}
	req.Trailer = http.Header{"X-T": {"t"}}
	if got, err := compValue(t, msg, "x-t;req;tr", nil); err != nil || got != "t" {
		t.Errorf("req trailer: %q %v", got, err)
	}
	for _, id := range []string{"@method", "@status;req"} {
		if _, err := compValue(t, msg, id, nil); !errors.Is(err, ErrInvalidComponent) {
			t.Errorf("%s: %v", id, err)
		}
	}
	bad := message{resp: &responseParts{status: 42, header: http.Header{}}}
	if _, err := compValue(t, bad, "@status", nil); !errors.Is(err, ErrMissingComponent) {
		t.Errorf("bad status: %v", err)
	}
	if _, err := compValue(t, bad, "@method;req", nil); !errors.Is(err, ErrMissingComponent) {
		t.Errorf("no request: %v", err)
	}
	if _, err := compValue(t, bad, "x;tr", nil); !errors.Is(err, ErrMissingComponent) {
		t.Errorf("no trailer: %v", err)
	}
}

func TestSignatureBaseErrors(t *testing.T) {
	req := readRequest(t, testRequest)
	r := &resolver{msg: message{req: req}}
	comps, _ := parseComponents([]string{"@method", `"@method"`})
	if _, err := r.signatureBase(comps, "()"); !errors.Is(err, ErrInvalidComponent) {
		t.Errorf("duplicate: %v", err)
	}
	req.Header.Set("X-Bin", "caf\xc3\xa9")
	comps, _ = parseComponents([]string{"x-bin"})
	if _, err := r.signatureBase(comps, "()"); !errors.Is(err, ErrMissingComponent) {
		t.Errorf("non-ascii: %v", err)
	}
	comps, _ = parseComponents([]string{"x-bin;bs"})
	if _, err := r.signatureBase(comps, "()"); err != nil {
		t.Errorf("bs should wrap non-ascii: %v", err)
	}
	comps, _ = parseComponents([]string{"nope"})
	if _, err := r.signatureBase(comps, "()"); !errors.Is(err, ErrMissingComponent) {
		t.Errorf("missing: %v", err)
	}
}

func TestComponentString(t *testing.T) {
	c, err := ParseComponent(` Content-Type;req `)
	if err != nil || c.String() != `"content-type";req` {
		t.Fatalf("%v %v", c, err)
	}
	if (Component{Name: "\x01"}).String() != `"\x01"` {
		t.Error("fallback quoting")
	}
}
