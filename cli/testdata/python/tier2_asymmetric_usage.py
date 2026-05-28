from gmssl import sm2
import ecies
from gostcrypto import gostsignature


# SM2 via gmssl (quantum-vulnerable)
# EXPECTED: SM2 | pke | | medium | quantum-vulnerable
def sm2_crypt():
    crypt_sm2 = sm2.CryptSM2(public_key="04...", private_key="00...")
    return crypt_sm2


# ECIES via eciespy (quantum-vulnerable)
# EXPECTED: ECIES | pke | | medium | quantum-vulnerable
def ecies_encrypt(pubkey, data):
    return ecies.encrypt(pubkey, data)


# ECIES decrypt
# EXPECTED: ECIES | pke | | medium | quantum-vulnerable
def ecies_decrypt(privkey, data):
    return ecies.decrypt(privkey, data)


# GOST R 34.10 signature via gostcrypto (quantum-vulnerable)
# EXPECTED: GOST R 34.10 | signature | | medium | quantum-vulnerable
def gost_sign():
    signer = gostsignature.new(
        gostsignature.MODE_256,
        gostsignature.CURVES_R_1323565_1_024_2019["id-tc26-gost-3410-2012-256-paramSetB"],
    )
    return signer
