// ECIES via eciesjs (quantum-vulnerable)
// EXPECTED: ECIES | pke | | info | quantum-vulnerable
const eciesjs = require('eciesjs');

function encryptMessage(pubkey, data) {
  return eciesjs.encrypt(pubkey, data);
}

function decryptMessage(privkey, data) {
  return eciesjs.decrypt(privkey, data);
}
