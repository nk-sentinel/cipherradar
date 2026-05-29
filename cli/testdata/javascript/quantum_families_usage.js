// Tier-3 quantum-vulnerable family fixtures (issue #33).
const { schnorr } = require('@noble/secp256k1');
const bls = require('@noble/bls12-381');

async function signTaproot(priv, msg) {
  // EXPECTED: Schnorr | signature | schnorr | info | quantum-vulnerable
  const sig = await schnorr.sign(msg, priv);
  return sig;
}

async function verifyTaproot(sig, msg, pub) {
  // EXPECTED: Schnorr | signature | schnorr | info | quantum-vulnerable
  return schnorr.verify(sig, msg, pub);
}

async function signBLS(priv, msg) {
  // EXPECTED: BLS12-381 | signature | bls | info | quantum-vulnerable
  const sig = await bls.sign(msg, priv);
  return sig;
}

async function aggregateBLS(sigs) {
  // EXPECTED: BLS12-381 | signature | bls | info | quantum-vulnerable
  return bls.aggregateSignatures(sigs);
}

module.exports = { signTaproot, verifyTaproot, signBLS, aggregateBLS };
