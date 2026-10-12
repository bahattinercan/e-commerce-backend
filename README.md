E-Commerce Backend (Node.js)

E-commerce frontend ve admin websiteleri için backend. Express + MongoDB (Mongoose).

## Kurulum

```bash
npm install          # bağımlılıkları kur
cp .env.example .env # Windows: copy .env.example .env
npm start            # http://localhost:4000
npm test             # güvenlik/oturum testleri (in-memory MongoDB)
```

Geliştirme sırasında otomatik yeniden başlatma için: `npm run dev`

## Ortam değişkenleri (`.env`)

| Değişken                | Açıklama                                                        |
| ----------------------- | --------------------------------------------------------------- |
| `MONGO_CONNECT`         | MongoDB bağlantı adresi, örn. `mongodb://127.0.0.1:27017/ecommerce` |
| `JWT_TOKEN`             | JWT imzalama anahtarı (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`) |
| `PORT`                  | Sunucu portu, varsayılan `4000`                                 |
| `HOST`                  | Yüklenen görsel URL'i için host, varsayılan `http://localhost`  |
| `CORS_ORIGINS`          | Virgülle ayrılmış izinli frontend adresleri                      |
| `JWT_ACCESS_EXPIRES_SEC`| Erişim token'ı ömrü (saniye), varsayılan `900` (15 dk)          |
| `REFRESH_TOKEN_DAYS`    | Refresh çerezinin ömrü (gün), varsayılan `7`                    |
| `COOKIE_SECURE`         | HTTPS arkasında `true`                                          |
| `COOKIE_SAMESITE`       | `strict` (varsayılan) / `lax` / `none`                          |

`.env` dosyası git'e girmez; zorunlu değişkenler eksikse sunucu açılışta anlaşılır bir hata verip kapanır.

## Oturum modeli (httpOnly cookie + refresh)

- `POST /login` ve `POST /signup` iki httpOnly çerez set eder:
  - `auth_token`: kısa ömürlü erişim token'ı (15 dk)
  - `refresh_token`: 7 günlük, sadece `/refresh` yolunda gönderilen, **tek kullanımlık** refresh token
- SPA token'ı hiç görmez: `credentials: "include"` ile istek atar, localStorage'da token yoktur.
- Erişim token'ı süresi dolunca uçlar `401 { code: "session_expired" }` döner; SPA `POST /refresh`
  ile oturumu sessizce yeniler. Refresh token her kullanımda rotate edilir (eskisi iptal).
- `POST /logout` her iki çerezi de temizler ve refresh kaydını veritabanından siler.
- Refresh token'lar veritabanında **SHA-256 hash** olarak saklanır; sızan DB kaydı token yerine geçmez.

> Üretimde SPA ve API **farklı domain**'lerdeyse `COOKIE_SAMESITE=none` + `COOKIE_SECURE=true`
> şart (SameSite=None, Secure olmadan çalışmaz) ve `CORS_ORIGINS`'e iki domain'i de yazın.

## Admin kullanıcısı oluşturma

Ürün ekleme/silme ve görsel yükleme uçları admin yetkisi ister:

```bash
npm run create-admin -- admin@example.com guclu-sifre
```

Kullanıcı yoksa oluşturur, varsa rolünü `admin` yapar ve şifresini günceller.
Admin paneli aynı `/login` uç noktasını kullanır, ardından `GET /adminVerify` ile
yetkiyi doğrular.

## API

| Metot | Yol               | Açıklama                                  | Yetki        |
| ----- | ----------------- | ----------------------------------------- | ------------ |
| GET   | `/`               | Sağlık kontrolü                           | —            |
| POST  | `/login`          | Giriş (`{ email, password }`)            | —            |
| POST  | `/signup`         | Kayıt (`{ username, email, password }`)  | —            |
| POST  | `/refresh`        | Oturumu yeniler (refresh çerezi)         | refresh çerezi |
| POST  | `/logout`         | Çerezleri temizler, refresh'i iptal eder | —            |
| GET   | `/me`             | Oturum bilgisi (`name, email, role`)     | oturum       |
| GET   | `/adminVerify`    | Admin yetki kontrolü                     | admin        |
| POST  | `/upload`         | Görsel yükleme (`product` alanı, max 5 MB) | admin      |
| GET   | `/images/:file`   | Yüklenen/demo görseller                  | —            |
| POST  | `/addProduct`     | Ürün ekler (id otomatik)                 | admin        |
| POST  | `/removeProduct`  | Ürün siler (`{ id, name }`)              | admin        |
| GET   | `/allProducts`    | Ürünler; `?page=2&limit=50` ile sayfalı (max 100), `X-Total-Count` header'ı | — |
| GET   | `/newCollections` | Son koleksiyon                           | —            |
| GET   | `/popularInWomen` | `women` kategorisinden ilk 4 ürün        | —            |
| POST  | `/addToCart`      | Sepete ekler (`{ itemId }`)              | oturum       |
| POST  | `/removeFromCart` | Sepetten düşer (`{ itemId }`)            | oturum       |
| POST  | `/getCart`        | Sepeti döner                             | oturum       |

Yetki hataları: `401` oturum yok/sona erdi, `403` admin yetkisi yok. Tüm hatalar JSON döner.
`/login`, `/signup`, `/refresh` rate limit'lidir (15 dakikada 20 istek).

## Güvenlik notları

- Şifreler bcrypt ile hash'lenir. Eski düz metin kayıtlar ilk başarılı girişte otomatik hash'e yükseltilir.
- Giriş yanıtı "kullanıcı yok" ve "şifre yanlış" için aynı mesajı verir (e-posta enumeration'ı engeli).
- Admin rolü token'dan değil, her istekte veritabanından okunur.
- `helmet`: CSP, nosniff, X-Frame-Options, referrer policy.
- CORS allowlist + `credentials: true`; allowlist dışı origin `403`.
- Yüklemeler: 5 MB limiti, sadece JPEG/PNG/WebP/GIF; uzantı istenen mimetype'ten üretilir (client filename güvenilmez).
- `/login`, `/signup`, `/refresh` için `express-rate-limit`.
- Demo görseller `seed/images/` içinde; runtime yüklemeler `upload/images/` (gitignore).

## Testler

```bash
npm test
```

`tests/security.test.js` in-memory MongoDB ile 15 test koşar: çerez bayrakları, token'ın body'de
dönmemesi, süresi dolmuş erişim token'ı → `session_expired`, refresh rotation, logout iptali,
yetki (403), pagination, sahte dosya yüklemesi, helmet başlıkları, CORS ve rate limit.

## Yapı

- `index.js` — sunucu, rotalar, middleware
- `models.js` — Mongoose şemaları (`Product`, `Users`, `RefreshToken`)
- `tests/security.test.js` — güvenlik/oturum testleri
- `scripts/create-admin.js` — admin oluşturma/yükseltme
