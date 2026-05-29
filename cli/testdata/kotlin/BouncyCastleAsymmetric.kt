import org.bouncycastle.crypto.engines.SM2Engine
import org.bouncycastle.crypto.signers.SM2Signer
import org.bouncycastle.crypto.engines.IESEngine
import org.bouncycastle.crypto.signers.ECGOST3410Signer

// SM2 public-key encryption (quantum-vulnerable)
// EXPECTED: SM2 | pke | | medium | quantum-vulnerable
fun sm2Encrypt() {
    val engine = SM2Engine()
}

// SM2 signature (quantum-vulnerable)
// EXPECTED: SM2 | signature | | medium | quantum-vulnerable
fun sm2Sign() {
    val signer = SM2Signer()
}

// ECIES (quantum-vulnerable)
// EXPECTED: ECIES | pke | | medium | quantum-vulnerable
fun ecies() {
    val engine = IESEngine(null, null, null)
}

// EC-GOST R 34.10 signature (quantum-vulnerable)
// EXPECTED: EC-GOST R 34.10 | signature | | medium | quantum-vulnerable
fun ecgost() {
    val signer = ECGOST3410Signer()
}
