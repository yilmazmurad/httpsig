package sfv

import (
	"errors"
	"math"
	"testing"
)

func TestDictionaryRoundTrip(t *testing.T) {
	cases := map[string]string{
		`a=1,    b=2;x=1;y=2,   c=(a   b   c)`: `a=1, b=2;x=1;y=2, c=(a b c)`,
		`a=1, b=2;x=1;y=2, c=(a   b    c), d`:  `a=1, b=2;x=1;y=2, c=(a b c), d`,
		`a=?0, b, c;foo=bar`:                   `a=?0, b, c;foo=bar`,
		`a=1,a=2`:                              `a=2`,
		`x=:aGVsbG8=:, y="q\"\\", z=4.50`:      `x=:aGVsbG8=:, y="q\"\\", z=4.5`,
		`d=@1659578233, ds=%"f%c3%bc%c3%bc"`:   `d=@1659578233, ds=%"f%c3%bc%c3%bc"`,
		`t=foo/bar:baz, n=-12, e=()`:           `t=foo/bar:baz, n=-12, e=()`,
		`p=(1 2);q=?0;r="s"`:                   `p=(1 2);q=?0;r="s"`,
		``:                                     ``,
		`a=1;b;c=1.0`:                          `a=1;b;c=1.0`,
	}
	for in, want := range cases {
		d, err := ParseDictionary(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		got, err := SerializeDictionary(d)
		if err != nil || got != want {
			t.Errorf("%q: got %q (%v), want %q", in, got, err, want)
		}
	}
}

func TestListAndItem(t *testing.T) {
	l, err := ParseList(`sugar, tea, (rum cola);x=1, :AQI=:`)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := SerializeList(l); s != `sugar, tea, (rum cola);x=1, :AQI=:` {
		t.Error(s)
	}
	it, err := ParseItem(`  "hello";a=1  `)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := SerializeItem(it); s != `"hello";a=1` {
		t.Error(s)
	}
	if v, ok := it.Params.Get("a"); !ok || v != int64(1) {
		t.Error("Get")
	}
	if _, ok := it.Params.Get("zz"); ok {
		t.Error("Get missing")
	}
	if s, _ := SerializeMember(InnerList{Items: []Item{{Value: 1}}}); s != "(1)" {
		t.Error(s)
	}
	d := Dictionary{{Key: "a", Value: Item{Value: true}}}
	if _, ok := d.Get("b"); ok {
		t.Error("dict get")
	}
	if l2, err := ParseList(""); err != nil || len(l2) != 0 {
		t.Error("empty list")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`a=1,`, `a=1 b=2`, `A=1`, `a=(1 2`, `a=(1,2)`, `a="unterminated`, `a="bad\q"`,
		"a=\"\x01\"", `a=?2`, `a=:abc`, `a=:ab$c:`, `a=1234567890123456`, `a=1234567890123.1`,
		`a=1.1234`, `a=1.`, `a=-`, `a=@1.5`, `a=%x`, `a=%"abc`, `a=%"%zz"`, `a=%"%c3"`,
		"a=%\"\x7f\"", `a=%"%a`, `a=#`, `a=1;`, `a=1;B`, `a=1;b=#`, `a="x\`, `a=@x`,
		`a=:a:`, `a=("x" #)`, `a=(1 2);B`,
	}
	for _, s := range bad {
		if _, err := ParseDictionary(s); !errors.Is(err, ErrParse) {
			t.Errorf("%q: expected parse error, got %v", s, err)
		}
	}
	for _, s := range []string{`a,`, `a b`, `#`, `(1`} {
		if _, err := ParseList(s); err == nil {
			t.Errorf("list %q: expected error", s)
		}
	}
	for _, s := range []string{`1 2`, `#`, `1;#`} {
		if _, err := ParseItem(s); err == nil {
			t.Errorf("item %q: expected error", s)
		}
	}
}

func TestSerializeErrors(t *testing.T) {
	bad := []any{
		int64(1e16), Decimal(math.NaN()), Decimal(1e13), "\x01", Token(""), Token("1a"),
		Token("a b"), struct{}{}, int64(-1e16),
	}
	for _, v := range bad {
		if _, err := SerializeItem(Item{Value: v}); !errors.Is(err, ErrSerialize) {
			t.Errorf("%#v: expected error, got %v", v, err)
		}
	}
	if _, err := SerializeDictionary(Dictionary{{Key: "A", Value: Item{Value: 1}}}); err == nil {
		t.Error("bad key")
	}
	if _, err := SerializeDictionary(Dictionary{{Key: "", Value: Item{Value: 1}}}); err == nil {
		t.Error("empty key")
	}
	if _, err := SerializeDictionary(Dictionary{{Key: "a", Value: 5}}); err == nil {
		t.Error("bad member")
	}
	if _, err := SerializeDictionary(Dictionary{{Key: "a", Value: Item{Value: true, Params: Params{{Key: "B", Value: 1}}}}}); err == nil {
		t.Error("bad param key")
	}
	if _, err := SerializeItem(Item{Value: 1, Params: Params{{Key: "b", Value: struct{}{}}}}); err == nil {
		t.Error("bad param value")
	}
	if _, err := SerializeList(List{InnerList{Items: []Item{{Value: struct{}{}}}}}); err == nil {
		t.Error("bad inner item")
	}
	if _, err := SerializeList(List{7}); err == nil {
		t.Error("bad list member")
	}
	if _, err := SerializeItem(Item{Value: Date(1e16)}); err == nil {
		t.Error("bad date")
	}
	if _, err := SerializeDictionary(Dictionary{{Key: "a", Value: InnerList{Items: []Item{{Value: struct{}{}}}}}}); err == nil {
		t.Error("bad dict inner")
	}
}

func TestSerializeBareTypes(t *testing.T) {
	cases := []struct {
		v    any
		want string
	}{
		{int64(-5), "-5"}, {7, "7"}, {Decimal(1.0005), "1.0"}, {Decimal(-2.5), "-2.5"},
		{Decimal(1.2345), "1.234"}, {false, "?0"}, {true, "?1"}, {[]byte{}, "::"},
		{Token("*foo"), "*foo"}, {Date(-1), "@-1"}, {DisplayString("a%\"\x00é"), `%"a%25%22%00%c3%a9"`},
		{"", `""`},
	}
	for _, c := range cases {
		got, err := SerializeItem(Item{Value: c.v})
		if err != nil || got != c.want {
			t.Errorf("%#v: got %q (%v), want %q", c.v, got, err, c.want)
		}
	}
}

func TestParamsSet(t *testing.T) {
	var p Params
	p = p.Set("a", int64(1))
	p = p.Set("b", int64(2))
	p = p.Set("a", int64(3))
	if s, _ := SerializeItem(Item{Value: true, Params: p}); s != "?1;a=3;b=2" {
		t.Error(s)
	}
}

func TestByteSequenceLenientPadding(t *testing.T) {
	it, err := ParseItem(`:aGk:`)
	if err != nil || string(it.Value.([]byte)) != "hi" {
		t.Fatalf("%v %v", it, err)
	}
}

func FuzzDictionary(f *testing.F) {
	f.Add(`a=1, b=2;x=1;y=2, c=(a b c)`)
	f.Add(`sig1=("@method");created=1;keyid="k"`)
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDictionary(s)
		if err != nil {
			return
		}
		out, err := SerializeDictionary(d)
		if err != nil {
			t.Fatalf("serialize parsed %q: %v", s, err)
		}
		d2, err := ParseDictionary(out)
		if err != nil {
			t.Fatalf("reparse %q: %v", out, err)
		}
		out2, _ := SerializeDictionary(d2)
		if out != out2 {
			t.Fatalf("not idempotent: %q vs %q", out, out2)
		}
	})
}
