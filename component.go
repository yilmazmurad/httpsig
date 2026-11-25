package httpsig

import (
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/yilmazmurad/httpsig/internal/sfv"
)

// FieldType is the Structured Field type of an HTTP field, used for the sf
// and key component parameters.
type FieldType int

// Structured field types.
const (
	FieldUnknown FieldType = iota
	FieldItem
	FieldList
	FieldDictionary
)

// knownFieldTypes lists registered structured fields whose type is known.
var knownFieldTypes = map[string]FieldType{
	"accept-ch":                    FieldList,
	"cache-status":                 FieldList,
	"cdn-cache-control":            FieldDictionary,
	"content-digest":               FieldDictionary,
	"cross-origin-embedder-policy": FieldItem,
	"cross-origin-opener-policy":   FieldItem,
	"origin-agent-cluster":         FieldItem,
	"priority":                     FieldDictionary,
	"proxy-status":                 FieldList,
	"repr-digest":                  FieldDictionary,
	"signature":                    FieldDictionary,
	"signature-input":              FieldDictionary,
	"want-content-digest":          FieldDictionary,
	"want-repr-digest":             FieldDictionary,
	"accept-signature":             FieldDictionary,
}

// Component is a parsed component identifier: a lowercase name plus ordered
// parameters (sf, key, bs, req, tr, name).
type Component struct {
	Name   string
	params sfv.Params
}

// String returns the serialized component identifier, e.g. "@query-param";name="Pet".
func (c Component) String() string {
	s, err := sfv.SerializeItem(sfv.Item{Value: c.Name, Params: c.params})
	if err != nil {
		return strconv.Quote(c.Name)
	}
	return s
}

func (c Component) flag(name string) bool {
	v, ok := c.params.Get(name)
	return ok && v == true
}

func (c Component) item() sfv.Item { return sfv.Item{Value: c.Name, Params: c.params} }

// ParseComponent parses a component identifier. Both the serialized form
// (`"@query-param";name="id"`, `"content-type"`) and a friendlier bare form
// (`@method`, `Content-Type`, `example-dict;key="a"`, `@authority;req`) are
// accepted. Bare field names are lowercased.
func ParseComponent(s string) (Component, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `"`) {
		name, rest, _ := strings.Cut(s, ";")
		if rest != "" {
			rest = ";" + rest
		}
		s = strconv.Quote(strings.ToLower(strings.TrimSpace(name))) + rest
	}
	it, err := sfv.ParseItem(s)
	if err != nil {
		return Component{}, fmt.Errorf("%w: %q: %v", ErrInvalidComponent, s, err)
	}
	return componentFromItem(it)
}

func componentFromItem(it sfv.Item) (Component, error) {
	name, ok := it.Value.(string)
	if !ok || name == "" {
		return Component{}, fmt.Errorf("%w: component name must be a non-empty string", ErrInvalidComponent)
	}
	if strings.ToLower(name) != name {
		return Component{}, fmt.Errorf("%w: component name %q must be lowercase", ErrInvalidComponent, name)
	}
	c := Component{Name: name, params: it.Params}
	if err := c.validate(); err != nil {
		return Component{}, err
	}
	return c, nil
}

func (c Component) validate() error {
	derived := strings.HasPrefix(c.Name, "@")
	for _, p := range c.params {
		switch p.Key {
		case "sf", "bs", "tr":
			if derived {
				return fmt.Errorf("%w: parameter %q not allowed on %s", ErrInvalidComponent, p.Key, c.Name)
			}
			if p.Value != true {
				return fmt.Errorf("%w: parameter %q must be a boolean flag", ErrInvalidComponent, p.Key)
			}
		case "req":
			if p.Value != true {
				return fmt.Errorf("%w: parameter req must be a boolean flag", ErrInvalidComponent)
			}
		case "key":
			if derived {
				return fmt.Errorf("%w: parameter key not allowed on %s", ErrInvalidComponent, c.Name)
			}
			if _, ok := p.Value.(string); !ok {
				return fmt.Errorf("%w: parameter key must be a string", ErrInvalidComponent)
			}
		case "name":
			if c.Name != "@query-param" {
				return fmt.Errorf("%w: parameter name only allowed on @query-param", ErrInvalidComponent)
			}
			if _, ok := p.Value.(string); !ok {
				return fmt.Errorf("%w: parameter name must be a string", ErrInvalidComponent)
			}
		default:
			return fmt.Errorf("%w: unknown parameter %q on %s", ErrInvalidComponent, p.Key, c.Name)
		}
	}
	if c.flag("bs") && (c.flag("sf") || hasParam(c.params, "key")) {
		return fmt.Errorf("%w: bs cannot be combined with sf or key", ErrInvalidComponent)
	}
	if derived {
		switch c.Name {
		case "@method", "@target-uri", "@authority", "@scheme", "@request-target",
			"@path", "@query", "@status":
		case "@query-param":
			if !hasParam(c.params, "name") {
				return fmt.Errorf("%w: @query-param requires a name parameter", ErrInvalidComponent)
			}
		case "@signature-params":
			return fmt.Errorf("%w: @signature-params cannot be a covered component", ErrInvalidComponent)
		default:
			return fmt.Errorf("%w: unknown derived component %s", ErrInvalidComponent, c.Name)
		}
	}
	return nil
}

func hasParam(p sfv.Params, k string) bool {
	_, ok := p.Get(k)
	return ok
}

// message is the target message of a signature operation.
type message struct {
	// req is the request message: the target for requests, or the related
	// request for responses (may be nil for responses).
	req *http.Request
	// resp is non-nil when the target message is a response.
	resp *responseParts
}

type responseParts struct {
	status  int
	header  http.Header
	trailer http.Header
}

type resolver struct {
	msg        message
	fieldTypes map[string]FieldType
}

func (r *resolver) fieldType(name string) FieldType {
	if t, ok := r.fieldTypes[name]; ok {
		return t
	}
	return knownFieldTypes[name]
}

func missing(c Component, why string) error {
	return fmt.Errorf("%w: %s: %s", ErrMissingComponent, c.String(), why)
}

// value computes the component value for c.
func (r *resolver) value(c Component) (string, error) {
	useReq := r.msg.resp == nil
	if c.flag("req") {
		if r.msg.resp == nil {
			return "", fmt.Errorf("%w: req parameter used on a request message", ErrInvalidComponent)
		}
		if r.msg.req == nil {
			return "", missing(c, "no related request available")
		}
		useReq = true
	}
	if strings.HasPrefix(c.Name, "@") {
		if c.Name == "@status" {
			if useReq {
				return "", fmt.Errorf("%w: @status is only valid for responses", ErrInvalidComponent)
			}
			s := r.msg.resp.status
			if s < 100 || s > 999 {
				return "", missing(c, "invalid status code")
			}
			return strconv.Itoa(s), nil
		}
		if !useReq {
			return "", fmt.Errorf("%w: %s requires the req parameter on responses", ErrInvalidComponent, c.Name)
		}
		return derivedValue(c, r.msg.req)
	}
	var h http.Header
	var values []string
	var ok bool
	tr := c.flag("tr")
	switch {
	case useReq && tr:
		h = r.msg.req.Trailer
	case useReq:
		h = r.msg.req.Header
	case tr:
		h = r.msg.resp.trailer
	default:
		h = r.msg.resp.header
	}
	values, ok = lookupField(h, c.Name)
	if !ok && !tr && useReq {
		values, ok = requestFieldFallback(r.msg.req, c.Name)
	}
	if !ok {
		return "", missing(c, "field not present")
	}
	for i, v := range values {
		values[i] = canonicalFieldValue(v)
	}
	if c.flag("bs") {
		l := make(sfv.List, len(values))
		for i, v := range values {
			l[i] = sfv.Item{Value: []byte(v)}
		}
		return sfv.SerializeList(l)
	}
	combined := strings.Join(values, ", ")
	if k, ok := c.params.Get("key"); ok {
		d, err := sfv.ParseDictionary(combined)
		if err != nil {
			return "", missing(c, "field is not a valid dictionary: "+err.Error())
		}
		m, ok := d.Get(k.(string))
		if !ok {
			return "", missing(c, "dictionary key not present")
		}
		return sfv.SerializeMember(m)
	}
	if c.flag("sf") {
		return r.strict(c, combined)
	}
	return combined, nil
}

func (r *resolver) strict(c Component, v string) (string, error) {
	switch r.fieldType(c.Name) {
	case FieldDictionary:
		d, err := sfv.ParseDictionary(v)
		if err != nil {
			return "", missing(c, err.Error())
		}
		return sfv.SerializeDictionary(d)
	case FieldList:
		l, err := sfv.ParseList(v)
		if err != nil {
			return "", missing(c, err.Error())
		}
		return sfv.SerializeList(l)
	case FieldItem:
		it, err := sfv.ParseItem(v)
		if err != nil {
			return "", missing(c, err.Error())
		}
		return sfv.SerializeItem(it)
	}
	return "", fmt.Errorf("%w: structured type of field %q is unknown (set FieldTypes)", ErrInvalidComponent, c.Name)
}

func lookupField(h http.Header, name string) ([]string, bool) {
	if h == nil {
		return nil, false
	}
	if v, ok := h[textproto.CanonicalMIMEHeaderKey(name)]; ok {
		return append([]string(nil), v...), true
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return append([]string(nil), v...), true
		}
	}
	return nil, false
}

// requestFieldFallback covers fields that net/http stores outside Header.
func requestFieldFallback(req *http.Request, name string) ([]string, bool) {
	switch name {
	case "host":
		if a := req.Host; a != "" {
			return []string{a}, true
		}
		if req.URL != nil && req.URL.Host != "" {
			return []string{req.URL.Host}, true
		}
	case "content-length":
		if req.ContentLength > 0 {
			return []string{strconv.FormatInt(req.ContentLength, 10)}, true
		}
	}
	return nil, false
}

// canonicalFieldValue trims surrounding whitespace and replaces obsolete line
// folding with a single space.
func canonicalFieldValue(v string) string {
	v = strings.Trim(v, " \t")
	if !strings.ContainsAny(v, "\r\n") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\r' || c == '\n' {
			// collapse surrounding whitespace into one space
			s := strings.TrimRight(b.String(), " \t")
			b.Reset()
			b.WriteString(s)
			for i+1 < len(v) && strings.IndexByte(" \t\r\n", v[i+1]) >= 0 {
				i++
			}
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func requestScheme(req *http.Request) string {
	if req.URL != nil && req.URL.Scheme != "" {
		return strings.ToLower(req.URL.Scheme)
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func requestAuthority(req *http.Request) string {
	a := req.Host
	if a == "" && req.URL != nil {
		a = req.URL.Host
	}
	a = strings.ToLower(a)
	host, port, err := net.SplitHostPort(a)
	if err == nil {
		scheme := requestScheme(req)
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			if strings.Contains(host, ":") {
				return "[" + host + "]"
			}
			return host
		}
	}
	return a
}

func requestPath(req *http.Request) string {
	if req.URL == nil {
		return "/"
	}
	p := req.URL.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

func requestQuery(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	return req.URL.RawQuery
}

func requestTarget(req *http.Request) string {
	if req.Method == http.MethodConnect {
		if req.URL != nil && req.URL.Host != "" {
			return req.URL.Host
		}
		return req.Host
	}
	if req.RequestURI != "" {
		return req.RequestURI
	}
	t := requestPath(req)
	if q := requestQuery(req); q != "" {
		t += "?" + q
	}
	return t
}

func derivedValue(c Component, req *http.Request) (string, error) {
	switch c.Name {
	case "@method":
		if req.Method == "" {
			return http.MethodGet, nil
		}
		return req.Method, nil
	case "@authority":
		a := requestAuthority(req)
		if a == "" {
			return "", missing(c, "request has no authority")
		}
		return a, nil
	case "@scheme":
		return requestScheme(req), nil
	case "@target-uri":
		a := requestAuthority(req)
		if a == "" {
			return "", missing(c, "request has no authority")
		}
		t := requestPath(req)
		if q := requestQuery(req); q != "" {
			t += "?" + q
		}
		return requestScheme(req) + "://" + a + t, nil
	case "@request-target":
		return requestTarget(req), nil
	case "@path":
		return requestPath(req), nil
	case "@query":
		return "?" + requestQuery(req), nil
	case "@query-param":
		v, _ := c.params.Get("name")
		return queryParam(c, requestQuery(req), v.(string))
	}
	return "", fmt.Errorf("%w: unknown derived component %s", ErrInvalidComponent, c.Name)
}

func queryParam(c Component, rawQuery, name string) (string, error) {
	found := 0
	var value string
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if formEncode(formDecode(k)) != name {
			continue
		}
		found++
		value = formEncode(formDecode(v))
	}
	switch found {
	case 0:
		return "", missing(c, "query parameter not present")
	case 1:
		return value, nil
	}
	return "", missing(c, "query parameter occurs more than once")
}

// formDecode implements application/x-www-form-urlencoded value decoding:
// '+' becomes space and valid percent escapes are decoded; invalid escapes
// are left as-is.
func formDecode(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b = append(b, ' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b = append(b, unhexByte(s[i+1])<<4|unhexByte(s[i+2]))
			i += 2
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhexByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// formEncode percent-encodes every byte outside the
// application/x-www-form-urlencoded safe set (ALPHA DIGIT * - . _), encoding
// space as %20 as shown in RFC 9421 §2.2.8.
func formEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '*' || c == '-' || c == '.' || c == '_' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}

// signatureBase builds the RFC 9421 §2.5 signature base.
func (r *resolver) signatureBase(comps []Component, sigParams string) ([]byte, error) {
	var b strings.Builder
	seen := make(map[string]bool, len(comps))
	for _, c := range comps {
		id := c.String()
		if seen[id] {
			return nil, fmt.Errorf("%w: duplicate component %s", ErrInvalidComponent, id)
		}
		seen[id] = true
		v, err := r.value(c)
		if err != nil {
			return nil, err
		}
		if err := checkASCII(v); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrMissingComponent, id, err)
		}
		b.WriteString(id)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(sigParams)
	return []byte(b.String()), nil
}

func checkASCII(s string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t') || c > 0x7e {
			return fmt.Errorf("component value contains non-ASCII or control byte 0x%02x", c)
		}
	}
	return nil
}
