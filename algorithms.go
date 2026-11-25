package httpsig

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"
	"io"
	"math/big"
)

// Algorithm is an HTTP Message Signature algorithm name from the
// "HTTP Signature Algorithms" registry (RFC 9421 §6.2).
type Algorithm string

// Registered algorithms supported by this package.
const (
	AlgRSAPSSSHA512    Algorithm = "rsa-pss-sha512"
	AlgRSAV15SHA256    Algorithm = "rsa-v1_5-sha256"
	AlgHMACSHA256      Algorithm = "hmac-sha256"
	AlgECDSAP256SHA256 Algorithm = "ecdsa-p256-sha256"
	AlgECDSAP384SHA384 Algorithm = "ecdsa-p384-sha384"
	AlgEd25519         Algorithm = "ed25519"
)

// Signer produces signatures over a signature base.
type Signer interface {
	// Algorithm reports the algorithm the signer implements.
	Algorithm() Algorithm
	// KeyID returns the key identifier placed in the keyid parameter
	// (may be empty).
	KeyID() string
	// Sign returns the raw signature bytes for the signature base.
	Sign(base []byte) ([]byte, error)
}

// Verifier checks signatures over a signature base.
type Verifier interface {
	// Algorithm reports the algorithm the verifier implements.
	Algorithm() Algorithm
	// Verify returns nil if sig is a valid signature of base.
	Verify(base, sig []byte) error
}

// KeyResolver looks up the verifier for a key identifier. alg is the value
// of the alg signature parameter, or "" if it was not present.
type KeyResolver interface {
	ResolveKey(ctx context.Context, keyID string, alg Algorithm) (Verifier, error)
}

// KeyResolverFunc adapts a function to the KeyResolver interface.
type KeyResolverFunc func(ctx context.Context, keyID string, alg Algorithm) (Verifier, error)

// ResolveKey calls f.
func (f KeyResolverFunc) ResolveKey(ctx context.Context, keyID string, alg Algorithm) (Verifier, error) {
	return f(ctx, keyID, alg)
}

// StaticKeys is a KeyResolver backed by a fixed map of key IDs to verifiers.
type StaticKeys map[string]Verifier

// ResolveKey returns the verifier registered for keyID.
func (s StaticKeys) ResolveKey(_ context.Context, keyID string, _ Algorithm) (Verifier, error) {
	v, ok := s[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
	}
	return v, nil
}

// randReader is the entropy source for randomized algorithms (tests may swap it).
var randReader io.Reader = rand.Reader

func invalidSig(alg Algorithm) error {
	return fmt.Errorf("%w (%s)", ErrInvalidSignature, alg)
}

// ---- HMAC ----

// HMAC implements hmac-sha256 and is both a Signer and a Verifier.
type HMAC struct {
	keyID string
	key   []byte
}

// NewHMACSHA256 returns an hmac-sha256 signer/verifier for the shared secret.
func NewHMACSHA256(keyID string, key []byte) (*HMAC, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("%w: empty HMAC key", ErrInvalidKey)
	}
	return &HMAC{keyID: keyID, key: append([]byte(nil), key...)}, nil
}

// Algorithm returns hmac-sha256.
func (h *HMAC) Algorithm() Algorithm { return AlgHMACSHA256 }

// KeyID returns the key identifier.
func (h *HMAC) KeyID() string { return h.keyID }

// Sign computes the HMAC-SHA256 of base.
func (h *HMAC) Sign(base []byte) ([]byte, error) {
	m := hmac.New(sha256.New, h.key)
	m.Write(base)
	return m.Sum(nil), nil
}

// Verify checks the MAC in constant time.
func (h *HMAC) Verify(base, sig []byte) error {
	want, _ := h.Sign(base)
	if !hmac.Equal(want, sig) {
		return invalidSig(AlgHMACSHA256)
	}
	return nil
}

// ---- Ed25519 ----

type ed25519Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

type ed25519Verifier struct{ key ed25519.PublicKey }

// NewEd25519Signer returns an ed25519 Signer.
func NewEd25519Signer(keyID string, key ed25519.PrivateKey) (Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: bad ed25519 private key size", ErrInvalidKey)
	}
	return &ed25519Signer{keyID: keyID, key: key}, nil
}

// NewEd25519Verifier returns an ed25519 Verifier.
func NewEd25519Verifier(key ed25519.PublicKey) (Verifier, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: bad ed25519 public key size", ErrInvalidKey)
	}
	return &ed25519Verifier{key: key}, nil
}

func (s *ed25519Signer) Algorithm() Algorithm { return AlgEd25519 }
func (s *ed25519Signer) KeyID() string        { return s.keyID }
func (s *ed25519Signer) Sign(base []byte) ([]byte, error) {
	return ed25519.Sign(s.key, base), nil
}

func (v *ed25519Verifier) Algorithm() Algorithm { return AlgEd25519 }
func (v *ed25519Verifier) Verify(base, sig []byte) error {
	if !ed25519.Verify(v.key, base, sig) {
		return invalidSig(AlgEd25519)
	}
	return nil
}

// ---- ECDSA ----

type ecdsaParams struct {
	alg  Algorithm
	hash func() hash.Hash
	size int
}

func ecdsaParamsFor(c elliptic.Curve) (ecdsaParams, error) {
	switch c {
	case elliptic.P256():
		return ecdsaParams{AlgECDSAP256SHA256, sha256.New, 32}, nil
	case elliptic.P384():
		return ecdsaParams{AlgECDSAP384SHA384, sha512.New384, 48}, nil
	}
	return ecdsaParams{}, fmt.Errorf("%w: unsupported ECDSA curve", ErrInvalidKey)
}

type ecdsaSigner struct {
	keyID string
	key   *ecdsa.PrivateKey
	p     ecdsaParams
}

type ecdsaVerifier struct {
	key *ecdsa.PublicKey
	p   ecdsaParams
}

// NewECDSASigner returns an ECDSA Signer. P-256 keys produce
// ecdsa-p256-sha256 and P-384 keys ecdsa-p384-sha384 signatures, encoded as
// the raw concatenation r||s as required by RFC 9421.
func NewECDSASigner(keyID string, key *ecdsa.PrivateKey) (Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil ECDSA key", ErrInvalidKey)
	}
	p, err := ecdsaParamsFor(key.Curve)
	if err != nil {
		return nil, err
	}
	return &ecdsaSigner{keyID: keyID, key: key, p: p}, nil
}

// NewECDSAVerifier returns an ECDSA Verifier for a P-256 or P-384 key.
func NewECDSAVerifier(key *ecdsa.PublicKey) (Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil ECDSA key", ErrInvalidKey)
	}
	p, err := ecdsaParamsFor(key.Curve)
	if err != nil {
		return nil, err
	}
	return &ecdsaVerifier{key: key, p: p}, nil
}

type ecdsaASN1 struct{ R, S *big.Int }

func (s *ecdsaSigner) Algorithm() Algorithm { return s.p.alg }
func (s *ecdsaSigner) KeyID() string        { return s.keyID }
func (s *ecdsaSigner) Sign(base []byte) ([]byte, error) {
	h := s.p.hash()
	h.Write(base)
	der, err := ecdsa.SignASN1(randReader, s.key, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	var rs ecdsaASN1
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		return nil, err
	}
	out := make([]byte, 2*s.p.size)
	rs.R.FillBytes(out[:s.p.size])
	rs.S.FillBytes(out[s.p.size:])
	return out, nil
}

func (v *ecdsaVerifier) Algorithm() Algorithm { return v.p.alg }
func (v *ecdsaVerifier) Verify(base, sig []byte) error {
	if len(sig) != 2*v.p.size {
		return invalidSig(v.p.alg)
	}
	der, err := asn1.Marshal(ecdsaASN1{
		R: new(big.Int).SetBytes(sig[:v.p.size]),
		S: new(big.Int).SetBytes(sig[v.p.size:]),
	})
	if err != nil {
		return invalidSig(v.p.alg)
	}
	h := v.p.hash()
	h.Write(base)
	if !ecdsa.VerifyASN1(v.key, h.Sum(nil), der) {
		return invalidSig(v.p.alg)
	}
	return nil
}

// ---- RSA ----

type rsaSigner struct {
	keyID string
	key   *rsa.PrivateKey
	pss   bool
}

type rsaVerifier struct {
	key *rsa.PublicKey
	pss bool
}

// NewRSAPSSSigner returns an rsa-pss-sha512 Signer (MGF1/SHA-512, 64-byte salt).
func NewRSAPSSSigner(keyID string, key *rsa.PrivateKey) (Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil RSA key", ErrInvalidKey)
	}
	return &rsaSigner{keyID: keyID, key: key, pss: true}, nil
}

// NewRSAPSSVerifier returns an rsa-pss-sha512 Verifier.
func NewRSAPSSVerifier(key *rsa.PublicKey) (Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil RSA key", ErrInvalidKey)
	}
	return &rsaVerifier{key: key, pss: true}, nil
}

// NewRSAv15Signer returns an rsa-v1_5-sha256 Signer (RSASSA-PKCS1-v1_5).
func NewRSAv15Signer(keyID string, key *rsa.PrivateKey) (Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil RSA key", ErrInvalidKey)
	}
	return &rsaSigner{keyID: keyID, key: key}, nil
}

// NewRSAv15Verifier returns an rsa-v1_5-sha256 Verifier.
func NewRSAv15Verifier(key *rsa.PublicKey) (Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil RSA key", ErrInvalidKey)
	}
	return &rsaVerifier{key: key}, nil
}

var pssOpts = &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512}

func (s *rsaSigner) Algorithm() Algorithm {
	if s.pss {
		return AlgRSAPSSSHA512
	}
	return AlgRSAV15SHA256
}
func (s *rsaSigner) KeyID() string { return s.keyID }
func (s *rsaSigner) Sign(base []byte) ([]byte, error) {
	if s.pss {
		d := sha512.Sum512(base)
		return rsa.SignPSS(randReader, s.key, crypto.SHA512, d[:], pssOpts)
	}
	d := sha256.Sum256(base)
	return rsa.SignPKCS1v15(nil, s.key, crypto.SHA256, d[:])
}

func (v *rsaVerifier) Algorithm() Algorithm {
	if v.pss {
		return AlgRSAPSSSHA512
	}
	return AlgRSAV15SHA256
}
func (v *rsaVerifier) Verify(base, sig []byte) error {
	var err error
	if v.pss {
		d := sha512.Sum512(base)
		err = rsa.VerifyPSS(v.key, crypto.SHA512, d[:], sig, pssOpts)
	} else {
		d := sha256.Sum256(base)
		err = rsa.VerifyPKCS1v15(v.key, crypto.SHA256, d[:], sig)
	}
	if err != nil {
		return invalidSig(v.Algorithm())
	}
	return nil
}
