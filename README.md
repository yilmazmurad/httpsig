English | [Türkçe](README.tr.md)

# httpsig

[![CI](https://github.com/yilmazmurad/httpsig/actions/workflows/ci.yml/badge.svg)](https://github.com/yilmazmurad/httpsig/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/yilmazmurad/httpsig.svg)](https://pkg.go.dev/github.com/yilmazmurad/httpsig)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A zero-dependency Go implementation of **[RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)** for `net/http`.
Sign and verify requests and responses, plug it in as a client `http.RoundTripper` or as server middleware.
It is tested against the RFC's own Appendix B test vectors.

## Features

- **Signature base construction** per RFC 9421 §2.5, with all derived components:
  `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`,
  `@query-param;name="…"`, `@status`
- **HTTP fields** with lowercased names, combined multi-line values, whitespace trimming and obs-fold handling
- **Component parameters**: `;sf` (strict structured-field re-serialization), `;key` (dictionary member),
  `;bs` (byte-sequence wrapping), `;req` (request components inside a response signature), `;tr` (trailers)
- **`Signature-Input` / `Signature`** as RFC 9651 Dictionaries, via a small built-in structured-field parser and serializer (fuzzed)
- **Signature parameters**: `created`, `expires`, `nonce`, `alg`, `keyid`, `tag`
- **Algorithms**: `hmac-sha256`, `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384` (raw `r||s`), `rsa-pss-sha512`, `rsa-v1_5-sha256`
- **Pluggable** `Signer` / `Verifier` interfaces (use HSMs, KMS, …) and a `KeyResolver` keyed by `keyid`
- **Verification policy**: required components, max age, clock skew, accepted algorithms, required `created`/`expires`/`nonce`,
  nonce replay hook, tag filtering, label selection
- **`net/http` integration**: verifying `Middleware` (with optional RFC 9530 `Content-Digest` body check),
  signing `Transport` (`http.RoundTripper`), `ResponseSigner` middleware and `SignResponseHeader`
- **Errors you can classify** with `errors.Is` (`ErrExpired`, `ErrInvalidSignature`, `ErrRequiredComponent`, …)
- Standard library only. Go 1.23+.

## Install

```sh
go get github.com/yilmazmurad/httpsig@latest
```

## Usage

### Sign a client request

```go
key, _ := httpsig.NewHMACSHA256("my-key", secret)

req, _ := http.NewRequest("POST", "https://api.example.com/orders?id=42", body)
req.Header.Set("Content-Type", "application/json")

err := httpsig.Sign(req, "sig1", key, httpsig.SignOptions{
	Components: []string{"@method", "@authority", "@path", `@query-param;name="id"`, "content-type"},
	ExpiresIn:  time.Minute,
	Nonce:      randomNonce(),
})
// Signature-Input: sig1=("@method" "@authority" "@path" "@query-param";name="id" "content-type");created=…;keyid="my-key";expires=…;nonce="…"
// Signature: sig1=:…:
```

Or sign every outgoing request automatically, adding a `Content-Digest` of the body:

```go
priv := loadEd25519Key()
signer, _ := httpsig.NewEd25519Signer("client-1", priv)

client := &http.Client{Transport: &httpsig.Transport{
	Signer:        signer,
	ContentDigest: httpsig.DigestSHA256, // adds Content-Digest (RFC 9530)
	Options: httpsig.SignOptions{
		Components: []string{"@method", "@authority", "@path", "@query", "content-digest", "content-type"},
		IncludeAlg: true,
	},
}}
```

### Verify requests with middleware

```go
verifier, _ := httpsig.NewEd25519Verifier(pub)

mw := httpsig.Middleware(httpsig.MiddlewareConfig{
	Verify: httpsig.VerifyOptions{
		Resolver:           httpsig.StaticKeys{"client-1": verifier}, // or a KeyResolverFunc backed by your DB
		RequiredComponents: []string{"@method", "@authority", "@path", "content-digest"},
		MaxAge:             5 * time.Minute,
		ClockSkew:          30 * time.Second,
		AcceptedAlgorithms: []httpsig.Algorithm{httpsig.AlgEd25519},
	},
	VerifyContentDigest: true, // body must match a covered Content-Digest
})

http.Handle("/hooks", mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	res, _ := httpsig.ResultFromContext(r.Context())
	log.Printf("signed by %s (%s)", res.KeyID, res.Algorithm)
})))
```

Failures get `401 Unauthorized` (`400` for malformed fields or digest mismatches) unless you set `ErrorHandler`.
For direct use, call `httpsig.Verify(r, opts)`. It returns a `*Result` or an error that wraps one of the sentinel errors.

### Sign responses

```go
// Inside a handler: sign before writing the header.
w.Header().Set("Content-Type", "application/json")
err := httpsig.SignResponseHeader(w.Header(), http.StatusOK, r, "res", serverKey, httpsig.SignOptions{
	Components: []string{"@status", "content-type", "content-digest", "@method;req", "@path;req"},
})

// Or wrap a whole handler:
handler = httpsig.ResponseSigner("res", serverKey, opts)(handler)

// Client side: resp.Request provides the values for ;req components.
res, err := httpsig.VerifyResponse(resp, httpsig.VerifyOptions{Resolver: serverKeys})
```

### Structured fields

`;key` always parses the field as a Dictionary. For `;sf`, the field's structured type must be known.
Common registered fields are built in (`content-digest`, `repr-digest`, `signature`, `signature-input`, `priority`, `cache-status`, …).
Declare any others yourself:

```go
opts := httpsig.SignOptions{
	Components: []string{"example-dict;sf", `example-dict;key="b"`},
	FieldTypes: map[string]httpsig.FieldType{"example-dict": httpsig.FieldDictionary},
}
```

## Supported algorithms

| Algorithm            | Constructor(s)                                  | Notes                                  |
|----------------------|-------------------------------------------------|----------------------------------------|
| `hmac-sha256`        | `NewHMACSHA256` (signer + verifier)             | constant-time comparison               |
| `ed25519`            | `NewEd25519Signer`, `NewEd25519Verifier`        | deterministic                          |
| `ecdsa-p256-sha256`  | `NewECDSASigner`, `NewECDSAVerifier` (P-256)    | raw 64-byte `r‖s` encoding             |
| `ecdsa-p384-sha384`  | `NewECDSASigner`, `NewECDSAVerifier` (P-384)    | raw 96-byte `r‖s` encoding             |
| `rsa-pss-sha512`     | `NewRSAPSSSigner`, `NewRSAPSSVerifier`          | MGF1-SHA512, 64-byte salt              |
| `rsa-v1_5-sha256`    | `NewRSAv15Signer`, `NewRSAv15Verifier`          | deterministic                          |

You can add custom algorithms by implementing `Signer` / `Verifier`.

## Supported components

| Component                | Request | Response (`;req`) | Notes                                             |
|--------------------------|:-------:|:-----------------:|---------------------------------------------------|
| `@method`                | ✓       | ✓                 |                                                   |
| `@target-uri`            | ✓       | ✓                 | `scheme://authority/path?query`                   |
| `@authority`             | ✓       | ✓                 | lowercased, default port removed                  |
| `@scheme`                | ✓       | ✓                 | URL scheme, or `https` if `r.TLS != nil`          |
| `@request-target`        | ✓       | ✓                 | `RequestURI` on servers; authority for CONNECT    |
| `@path`, `@query`        | ✓       | ✓                 | `/` and `?` for empty values                      |
| `@query-param;name=`     | ✓       | ✓                 | WHATWG form decoding + re-encoding, unique names  |
| `@status`                | —       | ✓ (response only) |                                                   |
| header fields            | ✓       | ✓                 | `;sf`, `;key`, `;bs`, `;tr`, `;req`               |

`host` falls back to `r.Host` and `content-length` to `r.ContentLength`, because `net/http` keeps those outside `Header`.

## Limitations

- `@signature-params` cannot be covered, as required by the RFC. Unknown signature parameters are kept in the signature base and otherwise ignored.
- `;sf` needs the field's structured type (built-in list or `FieldTypes`). Unknown types produce `ErrInvalidComponent`, as the RFC requires.
- Components with the `;key` / `;sf` / `;bs` / `;tr` parameters on derived components are rejected. Other component parameters, such as those from future registry entries, are not supported.
- `@scheme` / `@target-uri` on servers are derived from `r.TLS`. Behind TLS-terminating proxies, avoid covering them or rewrite `r.URL.Scheme` before verifying.
- `ResponseSigner` signs at `WriteHeader` time. A response `Content-Digest` must be set by the handler before writing.
- Nonce replay storage is up to you (`VerifyOptions.NonceChecker`). The `Accept-Signature` negotiation field (RFC 9421 §5) is not implemented.
- `Content-Digest` helpers support `sha-256` and `sha-512` only.

## Testing

```sh
go test -race -cover ./...
go vet ./...
go test -run XXX -fuzz FuzzDictionary -fuzztime 30s ./internal/sfv
```

The suite includes the RFC 9421 Appendix B.2 test cases (B.2.1–B.2.6) and the §2.1–2.4 component examples.
It also covers the §2.4 request-response examples and the §4.3 multi-signature proxy example.
Deterministic algorithms (`ed25519`, `hmac-sha256`, `rsa-v1_5-sha256`) must match the published signatures byte-for-byte.
For randomized ones (`rsa-pss-sha512`, `ecdsa-p256-sha256`), the published signatures must verify and fresh signatures must round-trip.

## License

[MIT](LICENSE) © 2026 Murat Yılmaz
