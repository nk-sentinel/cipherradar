using System;
using System.Security.Cryptography;
using System.Net.Security;
using System.Security.Authentication;

namespace CipherRadarTest
{
    class CryptoUsage
    {
        // Good: AES encryption
        void EncryptAES()
        {
            var aes = Aes.Create();
            aes.Key = new byte[32];
            aes.GenerateIV();
        }

        // Bad: DES encryption (HIGH severity)
        void EncryptDES()
        {
            var des = DES.Create();
        }

        // Bad: Triple DES (HIGH severity)
        void EncryptTripleDES()
        {
            var tdes = TripleDES.Create();
        }

        // RSA key generation
        void GenerateRSA()
        {
            var rsa = RSA.Create(2048);
        }

        // ECDSA
        void GenerateECDSA()
        {
            var ecdsa = ECDsa.Create();
        }

        // Good: SHA-256 hash
        void HashSHA256()
        {
            var sha = SHA256.Create();
            sha.ComputeHash(new byte[0]);
        }

        // Bad: SHA-1 hash (HIGH severity)
        void HashSHA1()
        {
            var sha1 = SHA1.Create();
        }

        // Bad: MD5 hash (HIGH severity)
        void HashMD5()
        {
            var md5 = MD5.Create();
        }

        // HMAC-SHA256
        void MacHMACSHA256()
        {
            var hmac = new HMACSHA256(new byte[32]);
        }

        // PBKDF2 key derivation
        void DeriveKey()
        {
            var pbkdf2 = new Rfc2898DeriveBytes("password", new byte[16], 100000);
        }

        // Bad: TLS 1.0 (HIGH severity)
        void InsecureTLS()
        {
            var stream = new SslStream(null);
            stream.AuthenticateAsClient("host", null, SslProtocols.Tls, false);
        }

        // Bad: TLS 1.1 (HIGH severity)
        void DeprecatedTLS()
        {
            var stream = new SslStream(null);
            stream.AuthenticateAsClient("host", null, SslProtocols.Tls11, false);
        }

        // Good: TLS 1.2
        void SecureTLS12()
        {
            var stream = new SslStream(null);
            stream.AuthenticateAsClient("host", null, SslProtocols.Tls12, false);
        }

        // Good: TLS 1.3
        void SecureTLS13()
        {
            var stream = new SslStream(null);
            stream.AuthenticateAsClient("host", null, SslProtocols.Tls13, false);
        }

        // BouncyCastle.NET engines
        void BouncyCastleAES()
        {
            var engine = new AesEngine();
        }

        void BouncyCastleDES()
        {
            var engine = new DesEngine();
        }

        void BouncyCastleRSA()
        {
            var engine = new RsaEngine();
        }

        void BouncyCastleSha256()
        {
            var digest = new Sha256Digest();
        }

        void BouncyCastleMD5()
        {
            var digest = new MD5Digest();
        }

        // Constant propagation test
        const string Algorithm = "AES";
        void ConstPropTest()
        {
            var cipher = Aes.Create();
        }
    }
}
