package httpsig

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yilmazmurad/httpsig/internal/sfv"
)

// SignOptions controls signature creation.
//
// Signature parameters are emitted in the order created, keyid, alg,
// expires, nonce, tag (omitting unset ones).
type SignOptions struct {
	// Components lists the covered component identifiers in order, e.g.
	// "@method", "@authority", "@path", "content-digest",
	// `@query-param;name="id"`, "@status", "content-type;req".
	Components []string
	// Created is the creation time. If zero, Now() is used.
	Created time.Time
	// OmitCreated suppresses the created parameter.
	OmitCreated bool
	// Expires sets an absolute expiration time.
	Expires time.Time
	// ExpiresIn sets the expiration relative to the created time (used when
	// Expires is zero).
	ExpiresIn time.Duration
	// Nonce sets the nonce parameter.
	Nonce string
	// Tag sets the application-specific tag parameter.
	Tag string
	// KeyID overrides Signer.KeyID() for the keyid parameter.
	KeyID string
	// OmitKeyID suppresses the keyid parameter.
	OmitKeyID bool
	// IncludeAlg adds the alg parameter with the signer's algorithm.
	IncludeAlg bool
	// FieldTypes declares the structured type of fields used with the sf
	// parameter (names must be lowercase). Common registered fields such as
	// content-digest are known by default.
	FieldTypes map[string]FieldType
	// Now overrides the clock (defaults to time.Now).
	Now func() time.Time
}

func (o *SignOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func parseComponents(ids []string) ([]Component, error) {
	comps := make([]Component, 0, len(ids))
	for _, id := range ids {
		c, err := ParseComponent(id)
		if err != nil {
			return nil, err
		}
		comps = append(comps, c)
	}
	return comps, nil
}

func (o *SignOptions) signatureParams(comps []Component, s Signer) (sfv.InnerList, error) {
	il := sfv.InnerList{Items: make([]sfv.Item, len(comps))}
	for i, c := range comps {
		il.Items[i] = c.item()
	}
	created := o.Created
	if created.IsZero() {
		created = o.now()
	}
	if !o.OmitCreated {
		il.Params = append(il.Params, sfv.Param{Key: "created", Value: created.Unix()})
	}
	keyID := o.KeyID
	if keyID == "" {
		keyID = s.KeyID()
	}
	if keyID != "" && !o.OmitKeyID {
		il.Params = append(il.Params, sfv.Param{Key: "keyid", Value: keyID})
	}
	if o.IncludeAlg {
		il.Params = append(il.Params, sfv.Param{Key: "alg", Value: string(s.Algorithm())})
	}
	exp := o.Expires
	if exp.IsZero() && o.ExpiresIn > 0 {
		exp = created.Add(o.ExpiresIn)
	}
	if !exp.IsZero() {
		il.Params = append(il.Params, sfv.Param{Key: "expires", Value: exp.Unix()})
	}
	if o.Nonce != "" {
		il.Params = append(il.Params, sfv.Param{Key: "nonce", Value: o.Nonce})
	}
	if o.Tag != "" {
		il.Params = append(il.Params, sfv.Param{Key: "tag", Value: o.Tag})
	}
	return il, nil
}

// signMessage computes a signature and appends it to h under label.
func signMessage(msg message, h http.Header, label string, s Signer, o SignOptions) error {
	if s == nil {
		return fmt.Errorf("%w: nil signer", ErrInvalidKey)
	}
	if !validLabel(label) {
		return fmt.Errorf("%w: invalid label %q", ErrMalformed, label)
	}
	inputs, err := parseDictField(h, "Signature-Input")
	if err != nil {
		return err
	}
	sigs, err := parseDictField(h, "Signature")
	if err != nil {
		return err
	}
	if _, ok := inputs.Get(label); ok {
		return fmt.Errorf("%w: %q", ErrDuplicateLabel, label)
	}
	if _, ok := sigs.Get(label); ok {
		return fmt.Errorf("%w: %q", ErrDuplicateLabel, label)
	}
	comps, err := parseComponents(o.Components)
	if err != nil {
		return err
	}
	il, err := o.signatureParams(comps, s)
	if err != nil {
		return err
	}
	params, err := sfv.SerializeInnerList(il)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	r := &resolver{msg: msg, fieldTypes: o.FieldTypes}
	base, err := r.signatureBase(comps, params)
	if err != nil {
		return err
	}
	sig, err := s.Sign(base)
	if err != nil {
		return fmt.Errorf("httpsig: signing failed: %w", err)
	}
	sigItem, err := sfv.SerializeItem(sfv.Item{Value: sig})
	if err != nil {
		return err
	}
	appendDictField(h, "Signature-Input", label+"="+params)
	appendDictField(h, "Signature", label+"="+sigItem)
	return nil
}

func validLabel(l string) bool {
	_, err := sfv.SerializeDictionary(sfv.Dictionary{{Key: l, Value: sfv.Item{Value: int64(0)}}})
	return err == nil
}

func parseDictField(h http.Header, name string) (sfv.Dictionary, error) {
	vals := h.Values(name)
	if len(vals) == 0 {
		return nil, nil
	}
	d, err := sfv.ParseDictionary(strings.Join(vals, ", "))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, name, err)
	}
	return d, nil
}

func appendDictField(h http.Header, name, member string) {
	vals := h.Values(name)
	if len(vals) == 0 {
		h.Set(name, member)
		return
	}
	h.Set(name, strings.Join(vals, ", ")+", "+member)
}

// Sign signs the request r in place, adding Signature-Input and Signature
// header fields under label.
func Sign(r *http.Request, label string, s Signer, o SignOptions) error {
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	return signMessage(message{req: r}, r.Header, label, s, o)
}

// SignResponse signs resp in place. resp.Request is used as the related
// request for components carrying the req parameter.
func SignResponse(resp *http.Response, label string, s Signer, o SignOptions) error {
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	msg := message{req: resp.Request, resp: &responseParts{status: resp.StatusCode, header: resp.Header, trailer: resp.Trailer}}
	return signMessage(msg, resp.Header, label, s, o)
}

// SignResponseHeader signs a response that is about to be written by an
// http.Handler: header is the response header (typically w.Header()),
// status the status code that will be written, and req the request being
// served (used for components carrying the req parameter; may be nil).
func SignResponseHeader(header http.Header, status int, req *http.Request, label string, s Signer, o SignOptions) error {
	msg := message{req: req, resp: &responseParts{status: status, header: header}}
	return signMessage(msg, header, label, s, o)
}
