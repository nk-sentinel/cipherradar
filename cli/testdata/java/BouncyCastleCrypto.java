import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;

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
}
