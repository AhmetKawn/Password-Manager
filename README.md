# 🔐 Güvenli Yerel Şifre Yöneticisi (Secure Password Manager)

Python (Tkinter & Cryptography) ile geliştirilmiş, verilerinizi endüstri standardı şifreleme yöntemleriyle yerel olarak koruyan güvenli masaüstü şifre yöneticisi.

---

## ✨ Özellikler
Çok da bir özelliği yok zaten basit bişey ama kullanın çünkü canım öyle istiyo
Veritabanına erişim ve çözme işlemleri yalnızca sizin belirleyeceğiniz ana şifre ile mümkündür.
Şifreleriniz disk üzerinde ham metin olarak değil, **PBKDF2** anahtar türetme ve **Fernet (AES tabanlı)** şifreleme ile şifrelenmiş olarak saklanır (`vault.db`).
Yeni hesap eklerken tek tıkla yüksek güvenlikli, karmaşık rastgele şifreler üretebilirsiniz.
Kayıtlı şifrelerinizi güvenle panoya kopyalayarak sitelerde kullanabilirsiniz.
Bulut bağımlılığı yoktur;¨-beceremedim- tüm veriler tamamen sizin bilgisayarınızda şifreli olarak tutulur.
Kendim için yaptım kullanırsanız sevinirim ama.
---

## 🛠️ Kurulum

1. Depoyu klonlayın veya indirin:
   ```bash
   git clone [https://github.com/kullanici-adiniz/secure-password-manager.git](https://github.com/kullanici-adiniz/secure-password-manager.git)
   cd secure-password-manager
