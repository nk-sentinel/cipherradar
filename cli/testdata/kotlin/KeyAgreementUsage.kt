// Fixture for JCA KeyAgreement detection in Kotlin (issue #34, Tier-1 gap fill).
// Covers DH, ECDH, X25519, and X448 via KeyAgreement.getInstance().
import javax.crypto.KeyAgreement

class KeyAgreementUsage {
    fun dh() {
        val ka = KeyAgreement.getInstance("DH")
    }

    fun ecdh() {
        val ka = KeyAgreement.getInstance("ECDH")
    }

    fun x25519() {
        val ka = KeyAgreement.getInstance("X25519")
    }

    fun x448() {
        val ka = KeyAgreement.getInstance("X448")
    }
}
