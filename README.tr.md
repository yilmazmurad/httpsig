[English](README.md) | Türkçe

# httpsig

[![CI](https://github.com/yilmazmurad/httpsig/actions/workflows/ci.yml/badge.svg)](https://github.com/yilmazmurad/httpsig/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/yilmazmurad/httpsig.svg)](https://pkg.go.dev/github.com/yilmazmurad/httpsig)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`net/http` için **[RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)** standardının bağımlılıksız Go uygulaması.
İstekleri ve yanıtları imzalayıp doğrular; istemci tarafında `http.RoundTripper`, sunucu tarafında middleware olarak kullanılabilir.
RFC'nin kendi Ek B test vektörleriyle test edilmiştir.

## Özellikler

- RFC 9421 §2.5'e uygun **imza tabanı (signature base) oluşturma**. Tüm türetilmiş bileşenler desteklenir:
  `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`,
  `@query-param;name="…"`, `@status`
- **HTTP alanları**: küçük harfli adlar, birden çok satırın birleştirilmesi, boşluk kırpma, obs-fold düzeltmesi
- **Bileşen parametreleri**: `;sf` (katı structured-field yeniden serileştirme), `;key` (sözlük üyesi),
  `;bs` (byte-sequence sarmalama), `;req` (yanıt imzasında istek bileşenleri), `;tr` (trailer alanları)
- **`Signature-Input` / `Signature`** alanları RFC 9651 Dictionary olarak işlenir. Bunun için küçük, fuzz testinden geçmiş yerleşik bir structured-field ayrıştırıcı/serileştirici kullanılır.
- **İmza parametreleri**: `created`, `expires`, `nonce`, `alg`, `keyid`, `tag`
- **Algoritmalar**: `hmac-sha256`, `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384` (ham `r||s`), `rsa-pss-sha512`, `rsa-v1_5-sha256`
- **Takılabilir** `Signer` / `Verifier` arayüzleri (HSM, KMS vb.) ve `keyid` ile çalışan `KeyResolver`
- **Doğrulama politikası**: zorunlu bileşenler, en fazla yaş (max age), saat kayması toleransı, izin verilen algoritmalar,
  zorunlu `created`/`expires`/`nonce`, nonce tekrar (replay) kontrolü, tag filtresi, etiket seçimi
- **`net/http` entegrasyonu**: doğrulayan `Middleware` (isteğe bağlı RFC 9530 `Content-Digest` gövde kontrolüyle),
  imzalayan `Transport` (`http.RoundTripper`), `ResponseSigner` middleware ve `SignResponseHeader`
- `errors.Is` ile **sınıflandırılabilir hatalar** (`ErrExpired`, `ErrInvalidSignature`, `ErrRequiredComponent`, …)
- Yalnızca standart kütüphane. Go 1.23+.

## Kurulum

```sh
go get github.com/yilmazmurad/httpsig@latest
```

## Kullanım

### İstemci isteğini imzalama

```go
key, _ := httpsig.NewHMACSHA256("my-key", secret)

req, _ := http.NewRequest("POST", "https://api.example.com/orders?id=42", body)
req.Header.Set("Content-Type", "application/json")

err := httpsig.Sign(req, "sig1", key, httpsig.SignOptions{
	Components: []string{"@method", "@authority", "@path", `@query-param;name="id"`, "content-type"},
	ExpiresIn:  time.Minute,
	Nonce:      randomNonce(),
})
```

Giden tüm istekleri otomatik imzalamak ve gövdenin `Content-Digest` değerini eklemek için:

```go
signer, _ := httpsig.NewEd25519Signer("client-1", priv)

client := &http.Client{Transport: &httpsig.Transport{
	Signer:        signer,
	ContentDigest: httpsig.DigestSHA256, // Content-Digest ekler (RFC 9530)
	Options: httpsig.SignOptions{
		Components: []string{"@method", "@authority", "@path", "@query", "content-digest", "content-type"},
		IncludeAlg: true,
	},
}}
```

### Middleware ile istek doğrulama

```go
verifier, _ := httpsig.NewEd25519Verifier(pub)

mw := httpsig.Middleware(httpsig.MiddlewareConfig{
	Verify: httpsig.VerifyOptions{
		Resolver:           httpsig.StaticKeys{"client-1": verifier}, // veya veritabanına bağlı bir KeyResolverFunc
		RequiredComponents: []string{"@method", "@authority", "@path", "content-digest"},
		MaxAge:             5 * time.Minute,
		ClockSkew:          30 * time.Second,
		AcceptedAlgorithms: []httpsig.Algorithm{httpsig.AlgEd25519},
	},
	VerifyContentDigest: true, // gövde, imzalanmış Content-Digest ile eşleşmeli
})

http.Handle("/hooks", mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	res, _ := httpsig.ResultFromContext(r.Context())
	log.Printf("imzalayan: %s (%s)", res.KeyID, res.Algorithm)
})))
```

Doğrulama başarısız olursa `ErrorHandler` belirlenmedikçe `401 Unauthorized` döner. Bozuk alanlarda veya digest uyuşmazlığında `400` döner.
Doğrudan kullanmak için `httpsig.Verify(r, opts)` çağrılabilir. Fonksiyon bir `*Result` ya da sentinel hatalardan birini saran bir hata döndürür.

### Yanıt imzalama

```go
// Handler içinde, başlık yazılmadan önce imzalayın.
w.Header().Set("Content-Type", "application/json")
err := httpsig.SignResponseHeader(w.Header(), http.StatusOK, r, "res", serverKey, httpsig.SignOptions{
	Components: []string{"@status", "content-type", "content-digest", "@method;req", "@path;req"},
})

// Veya tüm handler'ı sarmalayın:
handler = httpsig.ResponseSigner("res", serverKey, opts)(handler)

// İstemci tarafı: ;req bileşenlerinin değerleri resp.Request'ten alınır.
res, err := httpsig.VerifyResponse(resp, httpsig.VerifyOptions{Resolver: serverKeys})
```

### Structured field'lar

`;key` parametresi alanı her zaman Dictionary olarak ayrıştırır. `;sf` için alanın structured tipinin bilinmesi gerekir.
Sık kullanılan kayıtlı alanlar yerleşiktir (`content-digest`, `repr-digest`, `signature`, `signature-input`, `priority`, `cache-status`, …).
Diğer alanları kendiniz tanımlayın:

```go
opts := httpsig.SignOptions{
	Components: []string{"example-dict;sf", `example-dict;key="b"`},
	FieldTypes: map[string]httpsig.FieldType{"example-dict": httpsig.FieldDictionary},
}
```

## Desteklenen algoritmalar

| Algoritma            | Yapıcı fonksiyon(lar)                           | Not                                    |
|----------------------|-------------------------------------------------|----------------------------------------|
| `hmac-sha256`        | `NewHMACSHA256` (imzalayıcı + doğrulayıcı)      | sabit zamanlı karşılaştırma            |
| `ed25519`            | `NewEd25519Signer`, `NewEd25519Verifier`        | deterministik                          |
| `ecdsa-p256-sha256`  | `NewECDSASigner`, `NewECDSAVerifier` (P-256)    | ham 64 baytlık `r‖s`                   |
| `ecdsa-p384-sha384`  | `NewECDSASigner`, `NewECDSAVerifier` (P-384)    | ham 96 baytlık `r‖s`                   |
| `rsa-pss-sha512`     | `NewRSAPSSSigner`, `NewRSAPSSVerifier`          | MGF1-SHA512, 64 bayt salt              |
| `rsa-v1_5-sha256`    | `NewRSAv15Signer`, `NewRSAv15Verifier`          | deterministik                          |

`Signer` / `Verifier` arayüzlerini uygulayarak kendi algoritmanızı ekleyebilirsiniz.

## Desteklenen bileşenler

| Bileşen                  | İstek | Yanıt (`;req`)     | Not                                                  |
|--------------------------|:-----:|:------------------:|------------------------------------------------------|
| `@method`                | ✓     | ✓                  |                                                      |
| `@target-uri`            | ✓     | ✓                  | `scheme://authority/path?query`                      |
| `@authority`             | ✓     | ✓                  | küçük harf, varsayılan port atılır                   |
| `@scheme`                | ✓     | ✓                  | URL şeması; `r.TLS != nil` ise `https`               |
| `@request-target`        | ✓     | ✓                  | sunucuda `RequestURI`; CONNECT için authority        |
| `@path`, `@query`        | ✓     | ✓                  | boşsa `/` ve `?`                                     |
| `@query-param;name=`     | ✓     | ✓                  | WHATWG form çözme + yeniden kodlama, tekil adlar     |
| `@status`                | —     | ✓ (yalnızca yanıt) |                                                      |
| başlık alanları          | ✓     | ✓                  | `;sf`, `;key`, `;bs`, `;tr`, `;req`                  |

`net/http` bu değerleri `Header` dışında tuttuğu için `host` için `r.Host`, `content-length` için `r.ContentLength` kullanılır.

## Sınırlamalar

- RFC gereği `@signature-params` kapsanamaz. Bilinmeyen imza parametreleri imza tabanında korunur, bunun dışında yok sayılır.
- `;sf` için alanın tipi bilinmelidir (yerleşik liste veya `FieldTypes`). Tip bilinmiyorsa RFC'nin istediği gibi `ErrInvalidComponent` döner.
- Türetilmiş bileşenlerde `;key` / `;sf` / `;bs` / `;tr` reddedilir. Gelecekte kayda girecek başka bileşen parametreleri desteklenmez.
- Sunucuda `@scheme` / `@target-uri` değerleri `r.TLS` üzerinden türetilir. TLS sonlandıran proxy arkasındaysanız bunları kapsamayın veya doğrulamadan önce `r.URL.Scheme` değerini ayarlayın.
- `ResponseSigner`, `WriteHeader` anında imzalar. Yanıtın `Content-Digest` değeri handler tarafından yazmadan önce ayarlanmalıdır.
- Nonce tekrarını saklama işi size aittir (`VerifyOptions.NonceChecker`). `Accept-Signature` müzakere alanı (RFC 9421 §5) uygulanmamıştır.
- `Content-Digest` yardımcıları yalnızca `sha-256` ve `sha-512` destekler.

## Testler

```sh
go test -race -cover ./...
go vet ./...
go test -run XXX -fuzz FuzzDictionary -fuzztime 30s ./internal/sfv
```

Test paketi, RFC 9421 Ek B.2 test vakalarını (B.2.1–B.2.6) ve §2.1–2.4 bileşen örneklerini içerir.
§2.4 istek-yanıt örnekleri ile §4.3 çoklu imzalı proxy örneği de test edilir.
Deterministik algoritmalar (`ed25519`, `hmac-sha256`, `rsa-v1_5-sha256`) yayımlanan imzalarla bayt bayt eşleşmek zorundadır.
Rastgele algoritmalarda (`rsa-pss-sha512`, `ecdsa-p256-sha256`) yayımlanan imzalar doğrulanır, yeni üretilen imzalar da gidiş-dönüş testinden geçer.

## Lisans

[MIT](LICENSE) © 2026 Murat Yılmaz
