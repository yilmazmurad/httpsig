package httpsig

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"

	"github.com/yilmazmurad/httpsig/internal/sfv"
)

// Content-Digest algorithms (RFC 9530) supported by the digest helpers.
const (
	DigestSHA256 = "sha-256"
	DigestSHA512 = "sha-512"
)

func digest(alg string, body []byte) ([]byte, error) {
	switch alg {
	case DigestSHA256:
		d := sha256.Sum256(body)
		return d[:], nil
	case DigestSHA512:
		d := sha512.Sum512(body)
		return d[:], nil
	}
	return nil, fmt.Errorf("%w: unsupported digest algorithm %q", ErrContentDigest, alg)
}

// ContentDigest returns an RFC 9530 Content-Digest field value for body,
// e.g. `sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:`.
func ContentDigest(alg string, body []byte) (string, error) {
	d, err := digest(alg, body)
	if err != nil {
		return "", err
	}
	return sfv.SerializeDictionary(sfv.Dictionary{{Key: alg, Value: sfv.Item{Value: d}}})
}

// VerifyContentDigest checks a Content-Digest field value against body.
// At least one supported algorithm (sha-256, sha-512) must be present and
// every supported algorithm present must match; unknown algorithms are ignored.
func VerifyContentDigest(field string, body []byte) error {
	d, err := sfv.ParseDictionary(field)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrContentDigest, err)
	}
	checked := 0
	for _, m := range d {
		if m.Key != DigestSHA256 && m.Key != DigestSHA512 {
			continue
		}
		it, ok := m.Value.(sfv.Item)
		if !ok {
			return fmt.Errorf("%w: %s is not a byte sequence", ErrContentDigest, m.Key)
		}
		got, ok := it.Value.([]byte)
		if !ok {
			return fmt.Errorf("%w: %s is not a byte sequence", ErrContentDigest, m.Key)
		}
		want, _ := digest(m.Key, body)
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return fmt.Errorf("%w: %s does not match body", ErrContentDigest, m.Key)
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("%w: no supported digest algorithm", ErrContentDigest)
	}
	return nil
}
