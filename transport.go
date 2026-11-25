package httpsig

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// Transport is an http.RoundTripper that signs every outgoing request.
type Transport struct {
	// Base is the underlying transport (http.DefaultTransport if nil).
	Base http.RoundTripper
	// Label is the signature label (default "sig1").
	Label string
	// Signer creates the signatures. Required.
	Signer Signer
	// Options controls the covered components and parameters.
	Options SignOptions
	// ContentDigest, if set to DigestSHA256 or DigestSHA512, buffers the
	// request body and adds a Content-Digest field before signing (cover it
	// by listing "content-digest" in Options.Components). Existing
	// Content-Digest fields are left untouched.
	ContentDigest string
}

// RoundTrip signs a clone of req and sends it with the base transport.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	closeBody := func() {
		if req.Body != nil {
			req.Body.Close()
		}
	}
	if t.Signer == nil {
		closeBody()
		return nil, errors.New("httpsig: Transport.Signer is nil")
	}
	r := req.Clone(req.Context())
	if t.ContentDigest != "" && r.Header.Get("Content-Digest") == "" {
		var body []byte
		if req.Body != nil && req.Body != http.NoBody {
			var err error
			body, err = io.ReadAll(req.Body)
			req.Body.Close()
			if err != nil {
				return nil, err
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
			r.ContentLength = int64(len(body))
		}
		d, err := ContentDigest(t.ContentDigest, body)
		if err != nil {
			closeBody()
			return nil, err
		}
		r.Header.Set("Content-Digest", d)
	}
	label := t.Label
	if label == "" {
		label = "sig1"
	}
	if err := Sign(r, label, t.Signer, t.Options); err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}
