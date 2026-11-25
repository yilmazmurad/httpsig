package httpsig

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/yilmazmurad/httpsig/internal/sfv"
)

// VerifyOptions is the verification policy.
type VerifyOptions struct {
	// Resolver resolves keyid values to verifiers. Required.
	Resolver KeyResolver
	// Label restricts verification to the signature with this label. If
	// empty, signatures are tried in order and the first one that satisfies
	// the policy and verifies is accepted.
	Label string
	// Tag, if set, only considers signatures whose tag parameter equals it.
	Tag string
	// RequiredComponents lists component identifiers that must be covered
	// (same syntax as SignOptions.Components).
	RequiredComponents []string
	// AcceptedAlgorithms, if non-empty, restricts the allowed algorithms.
	AcceptedAlgorithms []Algorithm
	// MaxAge, if > 0, rejects signatures whose created time is older than
	// MaxAge (and implies RequireCreated).
	MaxAge time.Duration
	// ClockSkew is the tolerance applied to created/expires checks.
	ClockSkew time.Duration
	// RequireCreated rejects signatures without a created parameter.
	RequireCreated bool
	// RequireExpires rejects signatures without an expires parameter.
	RequireExpires bool
	// RequireNonce rejects signatures without a nonce parameter.
	RequireNonce bool
	// NonceChecker, if set, is called with the nonce (possibly empty) of a
	// signature before cryptographic verification, e.g. to detect replays.
	NonceChecker func(ctx context.Context, nonce string) error
	// FieldTypes declares structured types for fields covered with sf.
	FieldTypes map[string]FieldType
	// Now overrides the clock (defaults to time.Now).
	Now func() time.Time
}

// Result describes a successfully verified signature.
type Result struct {
	Label      string
	KeyID      string
	Algorithm  Algorithm // algorithm of the verifier that validated the signature
	Created    time.Time // zero if absent
	Expires    time.Time // zero if absent
	Nonce      string
	Tag        string
	Components []string // serialized covered component identifiers
}

// Covers reports whether the signature covers the component identifier id
// (same syntax as SignOptions.Components).
func (r *Result) Covers(id string) bool {
	c, err := ParseComponent(id)
	if err != nil {
		return false
	}
	return slices.Contains(r.Components, c.String())
}

// Verify verifies a signature on the request r according to the policy.
func Verify(r *http.Request, o VerifyOptions) (*Result, error) {
	return verifyMessage(r.Context(), message{req: r}, r.Header, o)
}

// VerifyResponse verifies a signature on resp. resp.Request is used as the
// related request for components with the req parameter.
func VerifyResponse(resp *http.Response, o VerifyOptions) (*Result, error) {
	ctx := context.Background()
	if resp.Request != nil {
		ctx = resp.Request.Context()
	}
	msg := message{req: resp.Request, resp: &responseParts{status: resp.StatusCode, header: resp.Header, trailer: resp.Trailer}}
	return verifyMessage(ctx, msg, resp.Header, o)
}

func verifyMessage(ctx context.Context, msg message, h http.Header, o VerifyOptions) (*Result, error) {
	if o.Resolver == nil {
		return nil, fmt.Errorf("%w: no key resolver configured", ErrUnknownKey)
	}
	inputs, err := parseDictField(h, "Signature-Input")
	if err != nil {
		return nil, err
	}
	sigs, err := parseDictField(h, "Signature")
	if err != nil {
		return nil, err
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("%w: no Signature-Input field", ErrNoSignature)
	}
	required, err := parseComponents(o.RequiredComponents)
	if err != nil {
		return nil, err
	}
	var firstErr error
	tried := 0
	for _, m := range inputs {
		if o.Label != "" && m.Key != o.Label {
			continue
		}
		tried++
		res, err := verifyOne(ctx, msg, m, sigs, required, o)
		if err == nil {
			return res, nil
		}
		if o.Label != "" {
			return nil, err
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if tried == 0 {
		return nil, fmt.Errorf("%w: label %q", ErrNoSignature, o.Label)
	}
	return nil, firstErr
}

func malformed(label, format string, a ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrMalformed, label, fmt.Sprintf(format, a...))
}

func verifyOne(ctx context.Context, msg message, m sfv.DictMember, sigs sfv.Dictionary, required []Component, o VerifyOptions) (*Result, error) {
	label := m.Key
	il, ok := m.Value.(sfv.InnerList)
	if !ok {
		return nil, malformed(label, "Signature-Input member is not an inner list")
	}
	sv, ok := sigs.Get(label)
	if !ok {
		return nil, fmt.Errorf("%w: no Signature value for label %q", ErrNoSignature, label)
	}
	sigItem, ok := sv.(sfv.Item)
	if !ok {
		return nil, malformed(label, "Signature member is not a byte sequence")
	}
	sig, ok := sigItem.Value.([]byte)
	if !ok {
		return nil, malformed(label, "Signature member is not a byte sequence")
	}
	res := &Result{Label: label}
	comps := make([]Component, 0, len(il.Items))
	for _, it := range il.Items {
		c, err := componentFromItem(it)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		comps = append(comps, c)
		res.Components = append(res.Components, c.String())
	}
	var alg Algorithm
	for _, p := range il.Params {
		switch p.Key {
		case "created", "expires":
			n, ok := p.Value.(int64)
			if !ok {
				return nil, malformed(label, "%s must be an integer", p.Key)
			}
			if p.Key == "created" {
				res.Created = time.Unix(n, 0)
			} else {
				res.Expires = time.Unix(n, 0)
			}
		case "nonce", "alg", "keyid", "tag":
			s, ok := p.Value.(string)
			if !ok {
				return nil, malformed(label, "%s must be a string", p.Key)
			}
			switch p.Key {
			case "nonce":
				res.Nonce = s
			case "alg":
				alg = Algorithm(s)
			case "keyid":
				res.KeyID = s
			case "tag":
				res.Tag = s
			}
		}
		// Unknown parameters are ignored (they are still covered by the
		// signature through @signature-params).
	}

	// Policy checks before doing any cryptography.
	if o.Tag != "" && res.Tag != o.Tag {
		return nil, fmt.Errorf("%w: %s: tag %q does not match %q", ErrPolicy, label, res.Tag, o.Tag)
	}
	for _, rc := range required {
		if !slices.Contains(res.Components, rc.String()) {
			return nil, fmt.Errorf("%w: %s: %s", ErrRequiredComponent, label, rc.String())
		}
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	if (o.RequireCreated || o.MaxAge > 0) && res.Created.IsZero() {
		return nil, fmt.Errorf("%w: %s: created parameter required", ErrPolicy, label)
	}
	if o.RequireExpires && res.Expires.IsZero() {
		return nil, fmt.Errorf("%w: %s: expires parameter required", ErrPolicy, label)
	}
	if o.RequireNonce && res.Nonce == "" {
		return nil, fmt.Errorf("%w: %s: nonce parameter required", ErrPolicy, label)
	}
	if !res.Created.IsZero() && res.Created.After(now.Add(o.ClockSkew)) {
		return nil, fmt.Errorf("%w: %s", ErrNotYetValid, label)
	}
	if !res.Expires.IsZero() && now.After(res.Expires.Add(o.ClockSkew)) {
		return nil, fmt.Errorf("%w: %s: expired at %s", ErrExpired, label, res.Expires.UTC().Format(time.RFC3339))
	}
	if o.MaxAge > 0 && now.Sub(res.Created) > o.MaxAge+o.ClockSkew {
		return nil, fmt.Errorf("%w: %s: older than %s", ErrExpired, label, o.MaxAge)
	}
	if alg != "" && len(o.AcceptedAlgorithms) > 0 && !slices.Contains(o.AcceptedAlgorithms, alg) {
		return nil, fmt.Errorf("%w: %s: %q", ErrAlgorithm, label, alg)
	}
	if o.NonceChecker != nil {
		if err := o.NonceChecker(ctx, res.Nonce); err != nil {
			return nil, fmt.Errorf("%w: %s: nonce: %w", ErrPolicy, label, err)
		}
	}

	v, err := o.Resolver.ResolveKey(ctx, res.KeyID, alg)
	if err != nil {
		if errors.Is(err, ErrUnknownKey) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %q: %w", ErrUnknownKey, res.KeyID, err)
	}
	if v == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, res.KeyID)
	}
	res.Algorithm = v.Algorithm()
	if alg != "" && alg != res.Algorithm {
		return nil, fmt.Errorf("%w: %s: alg %q does not match key algorithm %q", ErrAlgorithm, label, alg, res.Algorithm)
	}
	if len(o.AcceptedAlgorithms) > 0 && !slices.Contains(o.AcceptedAlgorithms, res.Algorithm) {
		return nil, fmt.Errorf("%w: %s: %q", ErrAlgorithm, label, res.Algorithm)
	}

	params, err := sfv.SerializeInnerList(il)
	if err != nil {
		return nil, malformed(label, "%v", err)
	}
	r := &resolver{msg: msg, fieldTypes: o.FieldTypes}
	base, err := r.signatureBase(comps, params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if err := v.Verify(base, sig); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidSignature, label, err)
	}
	return res, nil
}
