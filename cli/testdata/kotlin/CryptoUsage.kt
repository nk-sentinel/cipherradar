import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.Mac
import javax.net.ssl.SSLContext

fun encryptAES(key: ByteArray, data: ByteArray) {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
}

fun badDES(key: ByteArray, data: ByteArray) {
    val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
}

fun hashMD5(data: ByteArray): ByteArray {
    return MessageDigest.getInstance("MD5").digest(data)
}

fun hashSHA256(data: ByteArray): ByteArray {
    return MessageDigest.getInstance("SHA-256").digest(data)
}

fun generateRSAKey() {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
}

fun hmacSHA256(key: ByteArray, data: ByteArray) {
    val mac = Mac.getInstance("HmacSHA256")
}

fun secureTLS() {
    val ctx = SSLContext.getInstance("TLSv1.2")
}

fun insecureTLS() {
    val ctx = SSLContext.getInstance("TLSv1")
}

// Constant propagation test
const val ALGORITHM = "AES/CBC/PKCS5Padding"
fun constPropTest() {
    val cipher = Cipher.getInstance(ALGORITHM)
}
