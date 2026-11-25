// Package sfv implements a minimal, dependency-free parser and serializer for
// RFC 9651 Structured Field Values, sufficient for HTTP Message Signatures.
package sfv

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Token is a Structured Field Token bare item.
type Token string

// Decimal is a Structured Field Decimal bare item.
type Decimal float64

// Date is a Structured Field Date bare item (seconds since the Unix epoch).
type Date int64

// DisplayString is a Structured Field Display String bare item.
type DisplayString string

// Param is a single parameter (key and bare item value).
type Param struct {
	Key   string
	Value any
}

// Params is an ordered set of parameters.
type Params []Param

// Get returns the value of the parameter with the given key.
func (p Params) Get(key string) (any, bool) {
	for _, kv := range p {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return nil, false
}

// Set sets key to v, preserving the position of an existing key.
func (p Params) Set(key string, v any) Params {
	for i := range p {
		if p[i].Key == key {
			p[i].Value = v
			return p
		}
	}
	return append(p, Param{Key: key, Value: v})
}

// Item is a bare item with parameters.
type Item struct {
	Value  any
	Params Params
}

// InnerList is a list of items with parameters.
type InnerList struct {
	Items  []Item
	Params Params
}

// DictMember is a single dictionary member. Value is Item or InnerList.
type DictMember struct {
	Key   string
	Value any
}

// Dictionary is an ordered map of keys to Item or InnerList values.
type Dictionary []DictMember

// Get returns the member value for key.
func (d Dictionary) Get(key string) (any, bool) {
	for _, m := range d {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

// List is an ordered list of Item or InnerList members.
type List []any

// ErrParse is returned for all parse failures.
var ErrParse = errors.New("sfv: parse error")

// ErrSerialize is returned for values that cannot be serialized.
var ErrSerialize = errors.New("sfv: serialize error")

type parser struct {
	s string
	i int
}

func (p *parser) eof() bool { return p.i >= len(p.s) }

func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.i]
}

func (p *parser) skipSP() {
	for !p.eof() && p.s[p.i] == ' ' {
		p.i++
	}
}

func (p *parser) skipOWS() {
	for !p.eof() && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("%w at offset %d: %s", ErrParse, p.i, fmt.Sprintf(format, a...))
}

func (p *parser) finish() error {
	p.skipSP()
	if !p.eof() {
		return p.errf("unexpected trailing characters")
	}
	return nil
}

// ParseDictionary parses a Dictionary field value.
func ParseDictionary(s string) (Dictionary, error) {
	p := &parser{s: s}
	p.skipSP()
	var d Dictionary
	for !p.eof() {
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		var member any
		if p.peek() == '=' {
			p.i++
			member, err = p.itemOrInnerList()
		} else {
			var params Params
			params, err = p.params()
			member = Item{Value: true, Params: params}
		}
		if err != nil {
			return nil, err
		}
		replaced := false
		for i := range d {
			if d[i].Key == key {
				d[i].Value = member
				replaced = true
				break
			}
		}
		if !replaced {
			d = append(d, DictMember{Key: key, Value: member})
		}
		p.skipOWS()
		if p.eof() {
			return d, nil
		}
		if p.peek() != ',' {
			return nil, p.errf("expected comma")
		}
		p.i++
		p.skipOWS()
		if p.eof() {
			return nil, p.errf("trailing comma")
		}
	}
	return d, nil
}

// ParseList parses a List field value.
func ParseList(s string) (List, error) {
	p := &parser{s: s}
	p.skipSP()
	var l List
	for !p.eof() {
		m, err := p.itemOrInnerList()
		if err != nil {
			return nil, err
		}
		l = append(l, m)
		p.skipOWS()
		if p.eof() {
			return l, nil
		}
		if p.peek() != ',' {
			return nil, p.errf("expected comma")
		}
		p.i++
		p.skipOWS()
		if p.eof() {
			return nil, p.errf("trailing comma")
		}
	}
	return l, nil
}

// ParseItem parses an Item field value.
func ParseItem(s string) (Item, error) {
	p := &parser{s: s}
	p.skipSP()
	it, err := p.item()
	if err != nil {
		return Item{}, err
	}
	if err := p.finish(); err != nil {
		return Item{}, err
	}
	return it, nil
}

func (p *parser) itemOrInnerList() (any, error) {
	if p.peek() == '(' {
		return p.innerList()
	}
	return p.item()
}

func (p *parser) innerList() (InnerList, error) {
	p.i++ // '('
	var il InnerList
	for !p.eof() {
		p.skipSP()
		if p.peek() == ')' {
			p.i++
			params, err := p.params()
			if err != nil {
				return InnerList{}, err
			}
			il.Params = params
			return il, nil
		}
		it, err := p.item()
		if err != nil {
			return InnerList{}, err
		}
		il.Items = append(il.Items, it)
		if c := p.peek(); c != ' ' && c != ')' {
			return InnerList{}, p.errf("expected space or ')' in inner list")
		}
	}
	return InnerList{}, p.errf("unterminated inner list")
}

func (p *parser) item() (Item, error) {
	v, err := p.bareItem()
	if err != nil {
		return Item{}, err
	}
	params, err := p.params()
	if err != nil {
		return Item{}, err
	}
	return Item{Value: v, Params: params}, nil
}

func (p *parser) params() (Params, error) {
	var ps Params
	for p.peek() == ';' {
		p.i++
		p.skipSP()
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		var v any = true
		if p.peek() == '=' {
			p.i++
			v, err = p.bareItem()
			if err != nil {
				return nil, err
			}
		}
		ps = ps.Set(key, v)
	}
	return ps, nil
}

func isLCAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool   { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isTChar(c byte) bool {
	if isAlpha(c) || isDigit(c) {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func (p *parser) key() (string, error) {
	c := p.peek()
	if !isLCAlpha(c) && c != '*' {
		return "", p.errf("invalid key start")
	}
	start := p.i
	for !p.eof() {
		c := p.s[p.i]
		if !isLCAlpha(c) && !isDigit(c) && c != '_' && c != '-' && c != '.' && c != '*' {
			break
		}
		p.i++
	}
	return p.s[start:p.i], nil
}

func (p *parser) bareItem() (any, error) {
	c := p.peek()
	switch {
	case c == '-' || isDigit(c):
		return p.number()
	case c == '"':
		return p.str()
	case c == '*' || isAlpha(c):
		return p.token(), nil
	case c == ':':
		return p.bytes()
	case c == '?':
		return p.boolean()
	case c == '@':
		p.i++
		n, err := p.number()
		if err != nil {
			return nil, err
		}
		i, ok := n.(int64)
		if !ok {
			return nil, p.errf("date must be an integer")
		}
		return Date(i), nil
	case c == '%':
		return p.displayString()
	}
	return nil, p.errf("unexpected character %q", c)
}

func (p *parser) number() (any, error) {
	start := p.i
	neg := false
	if p.peek() == '-' {
		neg = true
		p.i++
	}
	if !isDigit(p.peek()) {
		return nil, p.errf("expected digit")
	}
	numStart := p.i
	isDec := false
	for !p.eof() {
		c := p.s[p.i]
		if isDigit(c) {
			p.i++
		} else if c == '.' && !isDec {
			if p.i-numStart > 12 {
				return nil, p.errf("decimal integer part too long")
			}
			isDec = true
			p.i++
		} else {
			break
		}
		if !isDec && p.i-numStart > 15 {
			return nil, p.errf("integer too long")
		}
		if isDec && p.i-numStart > 16 {
			return nil, p.errf("decimal too long")
		}
	}
	num := p.s[numStart:p.i]
	if !isDec {
		v, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			return nil, p.errf("bad integer")
		}
		if neg {
			v = -v
		}
		return v, nil
	}
	if num[len(num)-1] == '.' {
		return nil, p.errf("decimal ends with '.'")
	}
	if len(num)-strings.IndexByte(num, '.')-1 > 3 {
		return nil, p.errf("too many fractional digits")
	}
	f, err := strconv.ParseFloat(p.s[start:p.i], 64)
	if err != nil {
		return nil, p.errf("bad decimal")
	}
	return Decimal(f), nil
}

func (p *parser) str() (string, error) {
	p.i++ // '"'
	var b strings.Builder
	for !p.eof() {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '\\':
			if p.eof() {
				return "", p.errf("unterminated escape")
			}
			n := p.s[p.i]
			if n != '"' && n != '\\' {
				return "", p.errf("invalid escape")
			}
			b.WriteByte(n)
			p.i++
		case c == '"':
			return b.String(), nil
		case c < 0x20 || c > 0x7e:
			return "", p.errf("invalid string character")
		default:
			b.WriteByte(c)
		}
	}
	return "", p.errf("unterminated string")
}

func (p *parser) token() Token {
	start := p.i
	p.i++
	for !p.eof() {
		c := p.s[p.i]
		if !isTChar(c) && c != ':' && c != '/' {
			break
		}
		p.i++
	}
	return Token(p.s[start:p.i])
}

func (p *parser) bytes() ([]byte, error) {
	p.i++ // ':'
	end := strings.IndexByte(p.s[p.i:], ':')
	if end < 0 {
		return nil, p.errf("unterminated byte sequence")
	}
	enc := p.s[p.i : p.i+end]
	for i := 0; i < len(enc); i++ {
		c := enc[i]
		if !isAlpha(c) && !isDigit(c) && c != '+' && c != '/' && c != '=' {
			return nil, p.errf("invalid base64 character")
		}
	}
	p.i += end + 1
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(enc, "="))
		if err != nil {
			return nil, p.errf("invalid base64")
		}
	}
	return b, nil
}

func (p *parser) boolean() (bool, error) {
	p.i++ // '?'
	switch p.peek() {
	case '1':
		p.i++
		return true, nil
	case '0':
		p.i++
		return false, nil
	}
	return false, p.errf("invalid boolean")
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func (p *parser) displayString() (DisplayString, error) {
	p.i++ // '%'
	if p.peek() != '"' {
		return "", p.errf("expected '\"' after '%%'")
	}
	p.i++
	var b []byte
	for !p.eof() {
		c := p.s[p.i]
		p.i++
		switch {
		case c < 0x20 || c > 0x7e:
			return "", p.errf("invalid display string character")
		case c == '%':
			if p.i+2 > len(p.s) {
				return "", p.errf("truncated percent escape")
			}
			h, ok1 := unhex(p.s[p.i])
			l, ok2 := unhex(p.s[p.i+1])
			if !ok1 || !ok2 {
				return "", p.errf("invalid percent escape")
			}
			b = append(b, h<<4|l)
			p.i += 2
		case c == '"':
			if !utf8.Valid(b) {
				return "", p.errf("invalid UTF-8 in display string")
			}
			return DisplayString(b), nil
		default:
			b = append(b, c)
		}
	}
	return "", p.errf("unterminated display string")
}

// --- Serialization ---

func serr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrSerialize, fmt.Sprintf(format, a...))
}

// SerializeDictionary serializes a Dictionary.
func SerializeDictionary(d Dictionary) (string, error) {
	var b strings.Builder
	for i, m := range d {
		if i > 0 {
			b.WriteString(", ")
		}
		if err := writeKey(&b, m.Key); err != nil {
			return "", err
		}
		if it, ok := m.Value.(Item); ok && it.Value == true {
			if err := writeParams(&b, it.Params); err != nil {
				return "", err
			}
			continue
		}
		b.WriteByte('=')
		if err := writeMember(&b, m.Value); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// SerializeList serializes a List.
func SerializeList(l List) (string, error) {
	var b strings.Builder
	for i, m := range l {
		if i > 0 {
			b.WriteString(", ")
		}
		if err := writeMember(&b, m); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// SerializeItem serializes an Item.
func SerializeItem(it Item) (string, error) {
	var b strings.Builder
	if err := writeItem(&b, it); err != nil {
		return "", err
	}
	return b.String(), nil
}

// SerializeMember serializes an Item or InnerList.
func SerializeMember(m any) (string, error) {
	var b strings.Builder
	if err := writeMember(&b, m); err != nil {
		return "", err
	}
	return b.String(), nil
}

// SerializeInnerList serializes an InnerList.
func SerializeInnerList(il InnerList) (string, error) {
	return SerializeMember(il)
}

func writeMember(b *strings.Builder, m any) error {
	switch v := m.(type) {
	case Item:
		return writeItem(b, v)
	case InnerList:
		b.WriteByte('(')
		for i, it := range v.Items {
			if i > 0 {
				b.WriteByte(' ')
			}
			if err := writeItem(b, it); err != nil {
				return err
			}
		}
		b.WriteByte(')')
		return writeParams(b, v.Params)
	}
	return serr("unsupported member type %T", m)
}

func writeItem(b *strings.Builder, it Item) error {
	if err := writeBare(b, it.Value); err != nil {
		return err
	}
	return writeParams(b, it.Params)
}

func writeParams(b *strings.Builder, ps Params) error {
	for _, p := range ps {
		b.WriteByte(';')
		if err := writeKey(b, p.Key); err != nil {
			return err
		}
		if p.Value == true {
			continue
		}
		b.WriteByte('=')
		if err := writeBare(b, p.Value); err != nil {
			return err
		}
	}
	return nil
}

func writeKey(b *strings.Builder, k string) error {
	if k == "" || (!isLCAlpha(k[0]) && k[0] != '*') {
		return serr("invalid key %q", k)
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !isLCAlpha(c) && !isDigit(c) && c != '_' && c != '-' && c != '.' && c != '*' {
			return serr("invalid key %q", k)
		}
	}
	b.WriteString(k)
	return nil
}

const maxInt = 999_999_999_999_999

func writeBare(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case int64:
		return writeInt(b, x)
	case int:
		return writeInt(b, int64(x))
	case Decimal:
		return writeDecimal(b, float64(x))
	case string:
		for i := 0; i < len(x); i++ {
			if x[i] < 0x20 || x[i] > 0x7e {
				return serr("invalid string character")
			}
		}
		b.WriteByte('"')
		for i := 0; i < len(x); i++ {
			if x[i] == '"' || x[i] == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(x[i])
		}
		b.WriteByte('"')
	case Token:
		if x == "" || (!isAlpha(x[0]) && x[0] != '*') {
			return serr("invalid token %q", string(x))
		}
		for i := 1; i < len(x); i++ {
			if !isTChar(x[i]) && x[i] != ':' && x[i] != '/' {
				return serr("invalid token %q", string(x))
			}
		}
		b.WriteString(string(x))
	case []byte:
		b.WriteByte(':')
		b.WriteString(base64.StdEncoding.EncodeToString(x))
		b.WriteByte(':')
	case bool:
		if x {
			b.WriteString("?1")
		} else {
			b.WriteString("?0")
		}
	case Date:
		b.WriteByte('@')
		return writeInt(b, int64(x))
	case DisplayString:
		const hex = "0123456789abcdef"
		b.WriteString(`%"`)
		for i := 0; i < len(x); i++ {
			c := x[i]
			if c == '%' || c == '"' || c < 0x20 || c > 0x7e {
				b.WriteByte('%')
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
		b.WriteByte('"')
	default:
		return serr("unsupported bare item type %T", v)
	}
	return nil
}

func writeInt(b *strings.Builder, i int64) error {
	if i > maxInt || i < -maxInt {
		return serr("integer out of range")
	}
	b.WriteString(strconv.FormatInt(i, 10))
	return nil
}

func writeDecimal(b *strings.Builder, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return serr("invalid decimal")
	}
	r := math.RoundToEven(f*1000) / 1000
	if math.Abs(math.Trunc(r)) > 999_999_999_999 {
		return serr("decimal out of range")
	}
	s := strconv.FormatFloat(r, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	b.WriteString(s)
	return nil
}
