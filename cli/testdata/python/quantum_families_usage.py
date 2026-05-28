"""Tier-3 quantum-vulnerable family fixtures (issue #33)."""

from py_ecc.bls import G2ProofOfPossession as bls
from coincurve import PrivateKey


def sign_bls(sk, message):
    # EXPECTED: BLS12-381 | signature | bls | info | quantum-vulnerable
    sig = bls.Sign(sk, message)
    return sig


def verify_bls(pk, message, sig):
    # EXPECTED: BLS12-381 | signature | bls | info | quantum-vulnerable
    return bls.Verify(pk, message, sig)


def aggregate_bls(sigs):
    # EXPECTED: BLS12-381 | signature | bls | info | quantum-vulnerable
    return bls.Aggregate(sigs)


def sign_taproot(key: PrivateKey, msg: bytes) -> bytes:
    # EXPECTED: Schnorr | signature | schnorr | info | quantum-vulnerable
    return key.sign_schnorr(msg)


def verify_taproot(pub, sig, msg) -> bool:
    # EXPECTED: Schnorr | signature | schnorr | info | quantum-vulnerable
    return pub.verify_schnorr(sig, msg)
