import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.bouncycastle.crypto.agreement.ECMQVBasicAgreement;
import org.bouncycastle.crypto.signers.ECGDSASigner;
import org.bouncycastle.crypto.signers.ECKCDSASigner;
import org.bouncycastle.crypto.engines.PaillierEngine;

public class BouncyCastleCrypto {
    // GOOD: AES via BC
    public void aesEngine() {
        AESEngine engine = new AESEngine();
    }

    // BAD: DES via BC
    public void desEngine() {
        DESEngine engine = new DESEngine();
    }

    // AES-CBC via BC
    public void aesCBC() {
        CBCBlockCipher cipher = new CBCBlockCipher(new AESEngine());
    }

    // AES-GCM via BC
    public void aesGCM() {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
    }

    // GOOD: SHA-256 digest
    public void sha256() {
        SHA256Digest digest = new SHA256Digest();
    }

    // BAD: MD5 digest
    public void md5() {
        MD5Digest digest = new MD5Digest();
    }

    // GOOD: BLAKE2b digest (note BouncyCastle's mixed-case class name)
    public void blake2b() {
        Blake2bDigest digest = new Blake2bDigest(256);
    }

    // GOOD: BLAKE2s digest
    public void blake2s() {
        Blake2sDigest digest = new Blake2sDigest(256);
    }

    // SM2 public-key encryption (quantum-vulnerable)
    // EXPECTED: SM2 | pke | | medium | quantum-vulnerable
    public void sm2Encrypt() {
        SM2Engine engine = new SM2Engine();
    }

    // SM2 signature (quantum-vulnerable)
    // EXPECTED: SM2 | signature | | medium | quantum-vulnerable
    public void sm2Sign() {
        SM2Signer signer = new SM2Signer();
    }

    // ECIES (quantum-vulnerable)
    // EXPECTED: ECIES | pke | | medium | quantum-vulnerable
    public void ecies() {
        IESEngine engine = new IESEngine(null, null, null);
    }

    // EC-GOST R 34.10 signature (quantum-vulnerable)
    // EXPECTED: EC-GOST R 34.10 | signature | | medium | quantum-vulnerable
    public void ecgost() {
        ECGOST3410Signer signer = new ECGOST3410Signer();
    }

    // ECMQV authenticated key agreement (quantum-vulnerable, #41)
    // EXPECTED: ECMQV | key-exchange | ecmqv | medium | quantum-vulnerable
    public void ecmqv() {
        ECMQVBasicAgreement agreement = new ECMQVBasicAgreement();
    }

    // EC-GDSA signature (quantum-vulnerable, #41)
    // EXPECTED: EC-GDSA | signature | ec-gdsa | medium | quantum-vulnerable
    public void ecgdsa() {
        ECGDSASigner signer = new ECGDSASigner();
    }

    // EC-KCDSA signature (quantum-vulnerable, #41)
    // EXPECTED: EC-KCDSA | signature | ec-kcdsa | medium | quantum-vulnerable
    public void eckcdsa() {
        ECKCDSASigner signer = new ECKCDSASigner();
    }

    // Paillier homomorphic encryption (quantum-vulnerable, #41)
    // EXPECTED: Paillier | pke | paillier | medium | quantum-vulnerable
    public void paillier() {
        PaillierEngine engine = new PaillierEngine();
    }
}
