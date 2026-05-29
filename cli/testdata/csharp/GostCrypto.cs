using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;

public class GostCrypto
{
    // GOST R 34.10 signature via BouncyCastle (quantum-vulnerable)
    // EXPECTED: GOST3410 | signature | | info | quantum-vulnerable
    public void Sign()
    {
        var signer = new ECGost3410Signer();
        var kpg = new Gost3410KeyPairGenerator();
    }

    // GOST R 34.11 hash via BouncyCastle
    // EXPECTED: GOST3411 | hash | | info |
    public void Hash()
    {
        var digest = new Gost3411_2012_256Digest();
    }
}
