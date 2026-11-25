package httpsig

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yilmazmurad/httpsig/internal/sfv"
)

// Keys from RFC 9421 Appendix B.1.

const testKeyRSAPub = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----`

const testKeyRSAPriv = `-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----`

const testKeyRSAPSSPub = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----`

const testKeyRSAPSSPriv = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END PRIVATE KEY-----`

const testKeyECCPub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----`

const testKeyECCPriv = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----`

const testKeyEd25519Pub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`

const testKeyEd25519Priv = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`

const testSharedSecret = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="

func pemBytes(t testing.TB, s string) []byte {
	t.Helper()
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatal("bad PEM")
	}
	return b.Bytes
}

type testKeys struct {
	rsaPriv    *rsa.PrivateKey
	rsaPub     *rsa.PublicKey
	pssPriv    *rsa.PrivateKey
	pssPub     *rsa.PublicKey
	eccPriv    *ecdsa.PrivateKey
	eccPub     *ecdsa.PublicKey
	edPriv     ed25519.PrivateKey
	edPub      ed25519.PublicKey
	hmacSecret []byte
}

func loadKeys(t testing.TB) testKeys {
	t.Helper()
	var k testKeys
	var err error
	if k.rsaPriv, err = x509.ParsePKCS1PrivateKey(pemBytes(t, testKeyRSAPriv)); err != nil {
		t.Fatal(err)
	}
	if k.rsaPub, err = x509.ParsePKCS1PublicKey(pemBytes(t, testKeyRSAPub)); err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(pemBytes(t, testKeyRSAPSSPub))
	if err != nil {
		t.Fatal(err)
	}
	k.pssPub = pub.(*rsa.PublicKey)
	// The RSA-PSS private key uses the id-RSASSA-PSS OID, which
	// x509.ParsePKCS8PrivateKey does not accept; unwrap it manually.
	var p8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(pemBytes(t, testKeyRSAPSSPriv), &p8); err != nil {
		t.Fatal(err)
	}
	if k.pssPriv, err = x509.ParsePKCS1PrivateKey(p8.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if k.eccPriv, err = x509.ParseECPrivateKey(pemBytes(t, testKeyECCPriv)); err != nil {
		t.Fatal(err)
	}
	pub, err = x509.ParsePKIXPublicKey(pemBytes(t, testKeyECCPub))
	if err != nil {
		t.Fatal(err)
	}
	k.eccPub = pub.(*ecdsa.PublicKey)
	priv, err := x509.ParsePKCS8PrivateKey(pemBytes(t, testKeyEd25519Priv))
	if err != nil {
		t.Fatal(err)
	}
	k.edPriv = priv.(ed25519.PrivateKey)
	pub, err = x509.ParsePKIXPublicKey(pemBytes(t, testKeyEd25519Pub))
	if err != nil {
		t.Fatal(err)
	}
	k.edPub = pub.(ed25519.PublicKey)
	if k.hmacSecret, err = base64.StdEncoding.DecodeString(testSharedSecret); err != nil {
		t.Fatal(err)
	}
	return k
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func (k testKeys) resolver(t testing.TB) StaticKeys {
	return StaticKeys{
		"test-key-rsa":       must(NewRSAv15Verifier(k.rsaPub)),
		"test-key-rsa-pss":   must(NewRSAPSSVerifier(k.pssPub)),
		"test-key-ecc-p256":  must(NewECDSAVerifier(k.eccPub)),
		"test-key-ed25519":   must(NewEd25519Verifier(k.edPub)),
		"test-shared-secret": must(NewHMACSHA256("test-shared-secret", k.hmacSecret)),
	}
}

const testRequest = "POST /foo?param=Value&Pet=dog HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"Date: Tue, 20 Apr 2021 02:07:55 GMT\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\r\n" +
	"Content-Length: 18\r\n" +
	"\r\n" +
	`{"hello": "world"}`

const testResponse = "HTTP/1.1 200 OK\r\n" +
	"Date: Tue, 20 Apr 2021 02:07:56 GMT\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Digest: sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:\r\n" +
	"Content-Length: 23\r\n" +
	"\r\n" +
	`{"message": "good dog"}`

func readRequest(t testing.TB, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readResponse(t testing.TB, raw string, req *http.Request) *http.Response {
	t.Helper()
	r, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// unwrap joins RFC 8792 '\' line-wrapped text.
func unwrap(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	var b strings.Builder
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasSuffix(l, `\`) && i+1 < len(lines) {
			b.WriteString(strings.TrimSuffix(l, `\`))
			lines[i+1] = strings.TrimLeft(lines[i+1], " ")
			continue
		}
		b.WriteString(l)
		if i+1 < len(lines) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

var created1618884473 = time.Unix(1618884473, 0)

type rfcVector struct {
	name     string
	label    string
	keyID    string
	opts     SignOptions
	base     string
	input    string // Signature-Input member value
	sig      string // Signature member value (base64)
	response bool
	exact    bool // deterministic algorithm: signature must match byte-for-byte
}

var rfcVectors = []rfcVector{
	{
		name: "B.2.1 minimal rsa-pss-sha512", label: "sig-b21", keyID: "test-key-rsa-pss",
		opts: SignOptions{Created: created1618884473, Nonce: "b3k2pp5k7z-50gnwp.yemd"},
		base: `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss"\
  ;nonce="b3k2pp5k7z-50gnwp.yemd"`,
		input: `();created=1618884473\
  ;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`,
		sig: `d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem\
  LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG\
  52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx\
  2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6\
  UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3\
  +7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==`,
	},
	{
		name: "B.2.2 selective rsa-pss-sha512", label: "sig-b22", keyID: "test-key-rsa-pss",
		opts: SignOptions{Created: created1618884473, Tag: "header-example",
			Components: []string{"@authority", "content-digest", `@query-param;name="Pet"`}},
		base: `"@authority": example.com
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX\
  +TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"@query-param";name="Pet": dog
"@signature-params": ("@authority" "content-digest" \
  "@query-param";name="Pet")\
  ;created=1618884473;keyid="test-key-rsa-pss"\
  ;tag="header-example"`,
		input: `("@authority" "content-digest" \
  "@query-param";name="Pet");created=1618884473\
  ;keyid="test-key-rsa-pss";tag="header-example"`,
		sig: `LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ\
  EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT\
  8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA\
  RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd\
  4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK\
  UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==`,
	},
	{
		name: "B.2.3 full coverage rsa-pss-sha512", label: "sig-b23", keyID: "test-key-rsa-pss",
		opts: SignOptions{Created: created1618884473,
			Components: []string{"date", "@method", "@path", "@query", "@authority", "content-type", "content-digest", "content-length"}},
		base: `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@query": ?param=Value&Pet=dog
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX\
  +TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@query" \
  "@authority" "content-type" "content-digest" "content-length")\
  ;created=1618884473;keyid="test-key-rsa-pss"`,
		input: `("date" "@method" "@path" "@query" \
  "@authority" "content-type" "content-digest" "content-length")\
  ;created=1618884473;keyid="test-key-rsa-pss"`,
		sig: `bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB\
  iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU\
  xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1\
  pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9\
  bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z\
  JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==`,
	},
	{
		name: "B.2.4 response ecdsa-p256-sha256", label: "sig-b24", keyID: "test-key-ecc-p256", response: true,
		opts: SignOptions{Created: created1618884473,
			Components: []string{"@status", "content-type", "content-digest", "content-length"}},
		base: `"@status": 200
"content-type": application/json
"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ4\
  1QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
"content-length": 23
"@signature-params": ("@status" "content-type" "content-digest" \
  "content-length");created=1618884473;keyid="test-key-ecc-p256"`,
		input: `("@status" "content-type" \
  "content-digest" "content-length");created=1618884473\
  ;keyid="test-key-ecc-p256"`,
		sig: `wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NK\
  ocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==`,
	},
	{
		name: "B.2.5 hmac-sha256", label: "sig-b25", keyID: "test-shared-secret", exact: true,
		opts: SignOptions{Created: created1618884473,
			Components: []string{"date", "@authority", "content-type"}},
		base: `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@authority": example.com
"content-type": application/json
"@signature-params": ("date" "@authority" "content-type")\
  ;created=1618884473;keyid="test-shared-secret"`,
		input: `("date" "@authority" "content-type")\
  ;created=1618884473;keyid="test-shared-secret"`,
		sig: `pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=`,
	},
	{
		name: "B.2.6 ed25519", label: "sig-b26", keyID: "test-key-ed25519", exact: true,
		opts: SignOptions{Created: created1618884473,
			Components: []string{"date", "@method", "@path", "@authority", "content-type", "content-length"}},
		base: `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" \
  "content-type" "content-length");created=1618884473\
  ;keyid="test-key-ed25519"`,
		input: `("date" "@method" "@path" "@authority" \
  "content-type" "content-length");created=1618884473\
  ;keyid="test-key-ed25519"`,
		sig: `wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1\
  u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==`,
	},
}

func (k testKeys) signer(t testing.TB, keyID string) Signer {
	switch keyID {
	case "test-key-rsa":
		return must(NewRSAv15Signer(keyID, k.rsaPriv))
	case "test-key-rsa-pss":
		return must(NewRSAPSSSigner(keyID, k.pssPriv))
	case "test-key-ecc-p256":
		return must(NewECDSASigner(keyID, k.eccPriv))
	case "test-key-ed25519":
		return must(NewEd25519Signer(keyID, k.edPriv))
	case "test-shared-secret":
		return must(NewHMACSHA256(keyID, k.hmacSecret))
	}
	t.Fatalf("unknown key %s", keyID)
	return nil
}

func TestRFC9421AppendixB2(t *testing.T) {
	keys := loadKeys(t)
	at := func() time.Time { return created1618884473.Add(time.Minute) }
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			wantBase := unwrap(v.base)
			wantInput := unwrap(v.input)
			wantSig := unwrap(v.sig)

			// 1. The signature base we construct matches the RFC exactly.
			req := readRequest(t, testRequest)
			msg := message{req: req}
			if v.response {
				resp := readResponse(t, testResponse, req)
				msg = message{req: req, resp: &responseParts{status: resp.StatusCode, header: resp.Header}}
			}
			comps, err := parseComponents(v.opts.Components)
			if err != nil {
				t.Fatal(err)
			}
			il, _ := v.opts.signatureParams(comps, keys.signer(t, v.keyID))
			r := &resolver{msg: msg}
			params := must(sfv.SerializeInnerList(il))
			if params != wantInput {
				t.Errorf("signature params:\n got %s\nwant %s", params, wantInput)
			}
			base, err := r.signatureBase(comps, params)
			if err != nil {
				t.Fatal(err)
			}
			if string(base) != wantBase {
				t.Errorf("signature base:\n got:\n%s\nwant:\n%s", base, wantBase)
			}

			// 2. The RFC's published signature verifies.
			h := http.Header{}
			h.Set("Signature-Input", v.label+"="+wantInput)
			h.Set("Signature", v.label+"=:"+wantSig+":")
			vo := VerifyOptions{Resolver: keys.resolver(t), Now: at}
			if v.response {
				resp := readResponse(t, testResponse, req)
				resp.Header.Set("Signature-Input", h.Get("Signature-Input"))
				resp.Header.Set("Signature", h.Get("Signature"))
				if _, err := VerifyResponse(resp, vo); err != nil {
					t.Fatalf("verify RFC signature: %v", err)
				}
			} else {
				req := readRequest(t, testRequest)
				req.Header.Set("Signature-Input", h.Get("Signature-Input"))
				req.Header.Set("Signature", h.Get("Signature"))
				res, err := Verify(req, vo)
				if err != nil {
					t.Fatalf("verify RFC signature: %v", err)
				}
				if res.KeyID != v.keyID || res.Label != v.label {
					t.Errorf("result = %+v", res)
				}
			}

			// 3. Our own signature has the same Signature-Input and, for
			// deterministic algorithms, the same bytes; and it verifies.
			var gotInput, gotSig string
			if v.response {
				resp := readResponse(t, testResponse, req)
				if err := SignResponse(resp, v.label, keys.signer(t, v.keyID), v.opts); err != nil {
					t.Fatal(err)
				}
				gotInput, gotSig = resp.Header.Get("Signature-Input"), resp.Header.Get("Signature")
				if _, err := VerifyResponse(resp, vo); err != nil {
					t.Fatalf("verify own signature: %v", err)
				}
			} else {
				req := readRequest(t, testRequest)
				if err := Sign(req, v.label, keys.signer(t, v.keyID), v.opts); err != nil {
					t.Fatal(err)
				}
				gotInput, gotSig = req.Header.Get("Signature-Input"), req.Header.Get("Signature")
				if _, err := Verify(req, vo); err != nil {
					t.Fatalf("verify own signature: %v", err)
				}
			}
			if gotInput != v.label+"="+wantInput {
				t.Errorf("Signature-Input:\n got %s\nwant %s=%s", gotInput, v.label, wantInput)
			}
			if v.exact && gotSig != v.label+"=:"+wantSig+":" {
				t.Errorf("Signature:\n got %s\nwant %s=:%s:", gotSig, v.label, wantSig)
			}
		})
	}
}

// TestRFC9421Section4_3 covers the proxy example: rsa-v1_5-sha256 is
// deterministic and must match byte-for-byte; the client ECDSA signature
// over the original message must verify.
func TestRFC9421Section4_3(t *testing.T) {
	keys := loadKeys(t)
	req := readRequest(t, "POST /foo?param=Value&Pet=dog HTTP/1.1\r\n"+
		"Host: origin.host.internal.example\r\n"+
		"Date: Tue, 20 Apr 2021 02:07:56 GMT\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: 18\r\n"+
		"Forwarded: for=192.0.2.123;host=example.com;proto=https\r\n"+
		"Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\r\n"+
		"Signature-Input: sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"content-length\");created=1618884475;keyid=\"test-key-ecc-p256\"\r\n"+
		"Signature: sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:\r\n"+
		"\r\n"+`{"hello": "world"}`)
	// The client signature covered @authority=example.com, so it verifies
	// against the original (pre-proxy) message.
	orig := readRequest(t, testRequest)
	orig.Header["Signature-Input"] = req.Header["Signature-Input"]
	orig.Header["Signature"] = req.Header["Signature"]
	now := func() time.Time { return time.Unix(1618884480, 0) }
	if _, err := Verify(orig, VerifyOptions{Resolver: keys.resolver(t), Now: now}); err != nil {
		t.Fatalf("client sig1: %v", err)
	}
	// After the proxy changed the authority it must fail.
	if _, err := Verify(req, VerifyOptions{Resolver: keys.resolver(t), Now: now}); err == nil {
		t.Fatal("expected sig1 to fail after authority change")
	}
	opts := SignOptions{
		Components: []string{"@method", "@authority", "@path", "content-digest", "content-type", "content-length", "forwarded"},
		Created:    time.Unix(1618884480, 0),
		Expires:    time.Unix(1618884540, 0),
		IncludeAlg: true,
	}
	if err := Sign(req, "proxy_sig", keys.signer(t, "test-key-rsa"), opts); err != nil {
		t.Fatal(err)
	}
	wantSig := unwrap(`proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+\
  JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49G\
  wiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7\
  LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtf\
  lzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbL\
  Vdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:`)
	wantInput := `proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540`
	gotInput := req.Header.Get("Signature-Input")
	if !strings.HasSuffix(gotInput, ", "+wantInput) {
		t.Errorf("Signature-Input = %s", gotInput)
	}
	if gotSig := req.Header.Get("Signature"); !strings.HasSuffix(gotSig, ", "+wantSig) {
		t.Errorf("Signature:\n got %s\nwant suffix %s", gotSig, wantSig)
	}
	res, err := Verify(req, VerifyOptions{Resolver: keys.resolver(t), Label: "proxy_sig", Now: now,
		AcceptedAlgorithms: []Algorithm{AlgRSAV15SHA256}, RequireExpires: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Algorithm != AlgRSAV15SHA256 || res.Expires.Unix() != 1618884540 {
		t.Errorf("result = %+v", res)
	}
	// Without a label the first valid signature (proxy_sig) is accepted.
	res, err = Verify(req, VerifyOptions{Resolver: keys.resolver(t), Now: now})
	if err != nil || res.Label != "proxy_sig" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	// Past expiry it fails.
	late := func() time.Time { return time.Unix(1618884600, 0) }
	if _, err := Verify(req, VerifyOptions{Resolver: keys.resolver(t), Label: "proxy_sig", Now: late}); err == nil {
		t.Fatal("expected expiry")
	}
}

// TestRFC9421Section2_4 covers the request-response (req parameter) examples.
func TestRFC9421Section2_4(t *testing.T) {
	keys := loadKeys(t)
	resp503 := "HTTP/1.1 503 Service Unavailable\r\n" +
		"Date: Tue, 20 Apr 2021 02:07:56 GMT\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 62\r\n" +
		"Content-Digest: sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:\r\n" +
		"\r\n" + `{"busy": true, "message": "Your call is very important to us"}`
	now := func() time.Time { return time.Unix(1618884480, 0) }
	cases := []struct{ input, sig, base string }{
		{
			input: `reqres=("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req "content-digest";req);created=1618884479;keyid="test-key-ecc-p256"`,
			sig:   `reqres=:dMT/A/76ehrdBTD/2Xx8QuKV6FoyzEP/I9hdzKN8LQJLNgzU4W767HK05rx1i8meNQQgQPgQp8wq2ive3tV5Ag==:`,
			base: unwrap(`"@status": 503
"content-digest": sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObf\
  wnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:
"content-type": application/json
"@authority";req: example.com
"@method";req: POST
"@path";req: /foo
"content-digest";req: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A\
  2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"@signature-params": ("@status" "content-digest" "content-type" \
  "@authority";req "@method";req "@path";req "content-digest";req)\
  ;created=1618884479;keyid="test-key-ecc-p256"`),
		},
		{
			input: `reqres=("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req "@query";req "content-digest";req "content-type";req "content-length";req);created=1618884479;keyid="test-key-ecc-p256"`,
			sig:   `reqres=:C73J41GVKc+TYXbSobvZf0CmNcptRiWN+NY1Or0A36ISg6ymdRN6ZgR2QfrtopFNzqAyv+CeWrMsNbcV2Ojsgg==:`,
		},
	}
	for i, c := range cases {
		req := readRequest(t, testRequest)
		resp := readResponse(t, resp503, req)
		resp.Header.Set("Signature-Input", c.input)
		resp.Header.Set("Signature", c.sig)
		res, err := VerifyResponse(resp, VerifyOptions{Resolver: keys.resolver(t), Now: now,
			RequiredComponents: []string{"@status", "@method;req", "content-digest;req"}})
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !res.Covers(`"@authority";req`) {
			t.Errorf("case %d: Covers failed", i)
		}
		if c.base != "" {
			comps, _ := parseComponents([]string{"@status", "content-digest", "content-type", "@authority;req", "@method;req", "@path;req", "content-digest;req"})
			r := &resolver{msg: message{req: req, resp: &responseParts{status: 503, header: resp.Header}}}
			params := strings.TrimPrefix(c.input, "reqres=")
			base, err := r.signatureBase(comps, params)
			if err != nil || string(base) != c.base {
				t.Errorf("base mismatch (%v):\n%s\nwant\n%s", err, base, c.base)
			}
		}
		// Without the related request the req components cannot resolve.
		resp.Request = nil
		if _, err := VerifyResponse(resp, VerifyOptions{Resolver: keys.resolver(t), Now: now}); err == nil {
			t.Errorf("case %d: expected error without request", i)
		}
	}

	// The signed request of §2.4 (rsa-pss-sha512) verifies too.
	req := readRequest(t, testRequest)
	req.Header.Set("Signature-Input", `sig1=("@method" "@authority" "@path" "@query" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-rsa-pss"`)
	req.Header.Set("Signature", unwrap(`sig1=:e8UJ5wMiRaonlth5ERtE8GIiEH7Akcr493nQ07VPNo6y3qvjdK\
  t0fo8VHO8xXDjmtYoatGYBGJVlMfIp06eVMEyNW2I4vN7XDAz7m5v1108vGzaDljr\
  d0H8+SJ28g7bzn6h2xeL/8q+qUwahWA/JmC8aOC9iVnwbOKCc0WSrLgWQwTY6VLp4\
  2Qt7jjhYT5W7/wCvfK9A1VmHH1lJXsV873Z6hpxesd50PSmO+xaNeYvDLvVdZlhtw\
  5PCtUYzKjHqwmaQ6DEuM8udRjYsoNqp2xZKcuCO1nKc0V3RjpqMZLuuyVbHDAbCzr\
  0pg2d2VM/OC33JAU7meEjjaNz+d7LWPg==:`))
	if _, err := Verify(req, VerifyOptions{Resolver: keys.resolver(t), Now: now, AcceptedAlgorithms: []Algorithm{AlgRSAPSSSHA512}}); err != nil {
		t.Fatal(err)
	}
}
