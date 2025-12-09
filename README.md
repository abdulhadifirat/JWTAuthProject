(Türkçe)
JWTAuthProject
Bu proje, C# ve .NET tabanlı JWT kimlik doğrulama sistemi geliştirmek için hazırlanmıştır. Amaç, kullanıcıların güvenli bir şekilde giriş yapmasını, token üretmesini ve bu token ile API kaynaklarına erişmesini sağlamaktır.
🚀 Özellikler
- JWT tabanlı kimlik doğrulama
- Kullanıcı giriş ve kayıt işlemleri
- Token üretimi ve doğrulama
- Yetkilendirme mekanizması (role-based access)
- RESTful API desteği
🔧 Kurulum
git clone https://github.com/abdulhadifirat/JWTAuthProject.git
cd JWTAuthProject
- Visual Studio veya Rider ile açın
- JWTAuthProject.sln dosyasını çalıştırın
- Gerekli NuGet paketlerini yükleyin
📖 Kullanım
- /api/auth/login → Kullanıcı giriş yapar ve JWT token alır
- /api/auth/register → Yeni kullanıcı kaydı oluşturur
- Token, Authorization: Bearer <token> başlığı ile API çağrılarında kullanılır
🛠️ Teknolojiler
- C#
- .NET Core / .NET 5+
- Entity Framework
- JWT (JSON Web Token)
🤝 Katkı
Pull request gönderebilir veya issue açabilirsiniz.
📜 Lisans
Henüz lisans belirtilmemiştir.

(English)
JWTAuthProject
This project is a C# and .NET based JWT authentication system. The goal is to allow users to securely log in, generate tokens, and access API resources using those tokens.
🚀 Features
- JWT-based authentication
- User login and registration
- Token generation and validation
- Role-based authorization
- RESTful API support
🔧 Installation
git clone https://github.com/abdulhadifirat/JWTAuthProject.git
cd JWTAuthProject
- Open with Visual Studio or Rider
- Run JWTAuthProject.sln solution file
- Install required NuGet packages
📖 Usage
- /api/auth/login → User logs in and receives JWT token
- /api/auth/register → Creates a new user account
- Token must be included in API requests: Authorization: Bearer <token>
🛠️ Technologies
- C#
- .NET Core / .NET 5+
- Entity Framework
- JWT (JSON Web Token)
🤝 Contribution
You can submit pull requests or open issues.
📜 License
No license specified yet.
