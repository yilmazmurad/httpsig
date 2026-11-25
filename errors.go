package httpsig

import "errors"

// Sentinel errors. All errors returned by this package wrap one of these,
// so callers can use errors.Is to classify failures.
var (
	// ErrMalformed reports a syntactically invalid Signature or
	// Signature-Input field, or an invalid signature parameter.
	ErrMalformed = errors.New("httpsig: malformed signature fields")
	// ErrNoSignature reports that no (matching) signature is present.
	ErrNoSignature = errors.New("httpsig: no signature found")
	// ErrInvalidComponent reports an invalid or unsupported component identifier.
	ErrInvalidComponent = errors.New("httpsig: invalid component identifier")
	// ErrMissingComponent reports a covered component that cannot be
	// resolved from the message (e.g. an absent header field).
	ErrMissingComponent = errors.New("httpsig: component not present in message")
	// ErrRequiredComponent reports that the verification policy requires a
	// component that the signature does not cover.
	ErrRequiredComponent = errors.New("httpsig: required component not covered")
	// ErrExpired reports a signature past its expires time or max age.
	ErrExpired = errors.New("httpsig: signature expired")
	// ErrNotYetValid reports a created time in the future.
	ErrNotYetValid = errors.New("httpsig: signature created in the future")
	// ErrUnknownKey reports that the key resolver could not find a key.
	ErrUnknownKey = errors.New("httpsig: unknown key")
	// ErrAlgorithm reports a disallowed or mismatching algorithm.
	ErrAlgorithm = errors.New("httpsig: algorithm not allowed")
	// ErrInvalidSignature reports a cryptographic verification failure.
	ErrInvalidSignature = errors.New("httpsig: invalid signature")
	// ErrPolicy reports other policy failures (missing created, nonce, tag).
	ErrPolicy = errors.New("httpsig: signature rejected by policy")
	// ErrDuplicateLabel reports that the label is already used on the message.
	ErrDuplicateLabel = errors.New("httpsig: signature label already present")
	// ErrContentDigest reports a missing or mismatching Content-Digest.
	ErrContentDigest = errors.New("httpsig: content digest mismatch")
	// ErrInvalidKey reports an unusable key passed to a constructor.
	ErrInvalidKey = errors.New("httpsig: invalid key")
)
