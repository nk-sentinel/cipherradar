from phe import paillier
from phe import PaillierPublicKey, PaillierPrivateKey


# Paillier keypair generation via python-paillier / phe (quantum-vulnerable).
# EXPECTED: Paillier | pke | paillier | medium | quantum-vulnerable
def gen_keypair():
    public_key, private_key = paillier.generate_paillier_keypair()
    return public_key, private_key


# Paillier public key reconstruction (quantum-vulnerable).
# EXPECTED: Paillier | pke | paillier | medium | quantum-vulnerable
def load_public_key(n):
    return paillier.PaillierPublicKey(n=n)


# Paillier private key reconstruction (quantum-vulnerable).
# EXPECTED: Paillier | pke | paillier | medium | quantum-vulnerable
def load_private_key(pub, p, q):
    return PaillierPrivateKey(pub, p, q)
