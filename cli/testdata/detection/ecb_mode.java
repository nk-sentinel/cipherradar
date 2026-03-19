import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;

public class EcbMode {
    // BAD: ECB mode
    public void encryptECB(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
    }

    // BAD: RSA with PKCS1Padding
    public void rsaPKCS1(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    // BAD: PBKDF2 with low iterations
    public void weakPBKDF2() throws Exception {
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 1000, 256);
    }

    // GOOD: AES-GCM
    public void encryptGCM(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
