package httpsig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type ctxKey struct{}

// ResultFromContext returns the verified signature stored by Middleware.
func ResultFromContext(ctx context.Context) (*Result, bool) {
	r, ok := ctx.Value(ctxKey{}).(*Result)
	return r, ok
}

// MiddlewareConfig configures Middleware.
type MiddlewareConfig struct {
	// Verify is the verification policy applied to every request.
	Verify VerifyOptions
	// VerifyContentDigest, if true, requires requests with a body to carry a
	// Content-Digest field that is covered by the signature and matches the
	// body (sha-256 or sha-512). Requests without a body are allowed without
	// a digest.
	VerifyContentDigest bool
	// MaxBodyBytes bounds the body read for digest verification
	// (default 10 MiB).
	MaxBodyBytes int64
	// ErrorHandler handles verification failures. The default responds with
	// 401 Unauthorized (400 for malformed signature fields).
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// DefaultErrorHandler is the default Middleware error handler.
func DefaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	code := http.StatusUnauthorized
	msg := "signature verification failed"
	switch {
	case errors.Is(err, ErrMalformed):
		code = http.StatusBadRequest
		msg = "malformed signature"
	case errors.Is(err, ErrContentDigest):
		code = http.StatusBadRequest
		msg = "content digest mismatch"
	case errors.Is(err, ErrNoSignature):
		msg = "signature required"
	}
	http.Error(w, msg, code)
}

// Middleware returns net/http middleware that verifies incoming request
// signatures. On success the *Result is available via ResultFromContext.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	onErr := cfg.ErrorHandler
	if onErr == nil {
		onErr = DefaultErrorHandler
	}
	limit := cfg.MaxBodyBytes
	if limit <= 0 {
		limit = 10 << 20
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := Verify(r, cfg.Verify)
			if err != nil {
				onErr(w, r, err)
				return
			}
			if cfg.VerifyContentDigest {
				if err := checkRequestDigest(r, res, limit); err != nil {
					onErr(w, r, err)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, res)))
		})
	}
}

func checkRequestDigest(r *http.Request, res *Result, limit int64) error {
	field := r.Header.Values("Content-Digest")
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	if !hasBody && len(field) == 0 {
		return nil
	}
	if len(field) == 0 {
		return fmt.Errorf("%w: Content-Digest field required", ErrContentDigest)
	}
	if !res.Covers("content-digest") {
		return fmt.Errorf("%w: content-digest not covered by signature", ErrContentDigest)
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, limit+1))
		r.Body.Close()
		if err != nil {
			return fmt.Errorf("%w: reading body: %v", ErrContentDigest, err)
		}
		if int64(len(body)) > limit {
			return fmt.Errorf("%w: body exceeds %d bytes", ErrContentDigest, limit)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return VerifyContentDigest(joinValues(field), body)
}

func joinValues(v []string) string {
	var b bytes.Buffer
	for i, s := range v {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s)
	}
	return b.String()
}

// ResponseSigner returns middleware that signs every response written by the
// wrapped handler just before its header is sent. Components must refer to
// headers that are set before WriteHeader (or the first Write) is called; a
// Content-Digest must therefore be set by the handler itself. Components with
// the req parameter refer to the incoming request. If signing fails, a 500
// response is sent instead.
func ResponseSigner(label string, s Signer, o SignOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &signingWriter{ResponseWriter: w, req: r, label: label, signer: s, opts: o}
			next.ServeHTTP(sw, r)
			if !sw.wrote {
				sw.WriteHeader(http.StatusOK)
			}
		})
	}
}

type signingWriter struct {
	http.ResponseWriter
	req    *http.Request
	label  string
	signer Signer
	opts   SignOptions
	wrote  bool
	failed bool
}

func (s *signingWriter) WriteHeader(code int) {
	if s.wrote {
		return
	}
	s.wrote = true
	h := s.ResponseWriter.Header()
	if err := SignResponseHeader(h, code, s.req, s.label, s.signer, s.opts); err != nil {
		s.failed = true
		for k := range h {
			delete(h, k)
		}
		http.Error(s.ResponseWriter, "response signing failed", http.StatusInternalServerError)
		return
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *signingWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	if s.failed {
		return 0, errors.New("httpsig: response signing failed")
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap supports http.ResponseController.
func (s *signingWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
