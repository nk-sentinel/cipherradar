// Fixture for .NET BCL asymmetric factory detection (issue #34, Tier-1 gap fill).
// Covers DSA and ECDiffieHellman (ECDH) via the standard Create() factory.
using System.Security.Cryptography;

class AsymmetricUsage
{
    void MakeDsa()
    {
        var dsa = DSA.Create(2048);
    }

    void MakeEcdh()
    {
        var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    }
}
