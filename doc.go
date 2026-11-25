// Package httpsig implements RFC 9421 HTTP Message Signatures for net/http
// with no dependencies outside the Go standard library.
//
// It builds signature bases from derived components (@method, @target-uri,
// @authority, @scheme, @request-target, @path, @query, @query-param,
// @status) and HTTP fields (with the sf, key, bs, req and tr parameters),
// serializes Signature-Input and Signature as RFC 9651 Dictionaries, and
// supports the hmac-sha256, ed25519, ecdsa-p256-sha256, ecdsa-p384-sha384,
// rsa-pss-sha512 and rsa-v1_5-sha256 algorithms.
//
// Clients sign requests with Sign or Transport; servers verify them with
// Verify or Middleware, and can sign responses with SignResponseHeader or
// ResponseSigner. Clients verify signed responses with VerifyResponse.
package httpsig
