E-Commerce Backend (Node.js)

E-commerce frontend ve admin websiteleri için backend. Express + MongoDB (Mongoose).

## Kurulum

```bash
npm install          # bağımlılıkları kur
cp .env.example .env # Windows: copy .env.example .env
npm start            # http://localhost:4000
```

Geliştirme sırasında otomatik yeniden başlatma için: `npm run dev`

## Ortam değişkenleri (`.env`)

| Değişken        | Açıklama                                                        |
| --------------- | --------------------------------------------------------------- |
| `MONGO_CONNECT` | MongoDB bağlantı adresi, örn. `mongodb://127.0.0.1:27017/ecommerce` |
| `JWT_TOKEN`     | JWT imzalama anahtarı (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`) |
| `PORT`          | Sunucu portu, varsayılan `4000`                                  |
| `HOST`          | Yüklenen görsel URL'i için host, varsayılan `http://localhost`   |

`.env` dosyası git'e girmez; zorunlu değişkenler eksikse sunucu açılışta anlaşılır bir hata verip kapanır.

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
| POST  | `/upload`         | Görsel yükleme (`product` alanı, multipart) | admin       |
| GET   | `/images/:file`   | Yüklenen görselleri sunar                 | —            |
| GET   | `/adminVerify`    | Admin token doğrulaması                   | admin        |
| POST  | `/addProduct`     | Ürün ekler (id otomatik)                  | admin        |
| POST  | `/removeProduct`  | Ürün siler (`{ id, name }`)               | admin        |
| GET   | `/allProducts`    | Tüm ürünler                               | —            |
| GET   | `/newCollections` | Son koleksiyon                            | —            |
| GET   | `/popularInWomen` | `women` kategorisinden ilk 4 ürün         | —            |
| POST  | `/signup`         | Kayıt (`{ username, email, password }`)   | —            |
| POST  | `/login`          | Giriş (`{ email, password }`)             | —            |
| POST  | `/addToCart`      | Sepete ekler (`{ itemId }`)               | `auth-token` |
| POST  | `/removeFromCart` | Sepetten düşer (`{ itemId }`)             | `auth-token` |
| POST  | `/getCart`        | Sepeti döner                              | `auth-token` |

Kimlik doğrulama `auth-token` header'ındaki JWT ile yapılır. Yetki hataları:
`401` token yok/geçersiz, `403` admin yetkisi yok. Tüm hatalar JSON döner.

## Güvenlik notları

- Şifreler bcrypt ile hash'lenir (`bcryptjs`). Eski düz metin kayıtlar ilk başarılı
  girişte otomatik olarak hash'e yükseltilir.
- Admin rolü token'da değil, her istekte veritabanından okunur; rol değişikliği
  yeniden giriş gerektirmez.
- JWT'lerde son kullanma süresi (`expiresIn`) yoktur; eklemek isterseniz
  `jwt.sign(data, jwtToken, { expiresIn: "7d" })`.

## Yapı

- `index.js` — sunucu, rotalar, middleware
- `models.js` — Mongoose şemaları (`Product`, `Users`)
- `scripts/create-admin.js` — admin oluşturma/yükseltme
