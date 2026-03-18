import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;

public class JcaCrypto {
    // BAD: DES
    public void encryptDES(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
    }

    // BAD: AES-ECB
    public void encryptAESECB(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    // GOOD: AES-GCM
    public void encryptAESGCM(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }

    // BAD: MD5
    public byte[] hashMD5(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    // BAD: SHA-1
    public byte[] hashSHA1(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    // GOOD: SHA-256
    public byte[] hashSHA256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    // QUANTUM-VULNERABLE: RSA-2048
    public void generateRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    // QUANTUM-VULNERABLE: DSA
    public void generateDSAKey() throws Exception {
        KeyPairGenerator.getInstance("DSA");
    }

    // Signature
    public void signData() throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
    }

    // HMAC
    public void computeHMAC() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
    }

    // Constant propagation test
    public void constPropTest() throws Exception {
        String algo = "AES/CBC/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(algo);
    }
}
