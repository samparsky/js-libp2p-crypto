/**
 * @module libp2p-crypto/keys/ed25519
 */

'use strict'

const nacl = require('tweetnacl')

exports.publicKeyLength = nacl.sign.publicKeyLength
exports.privateKeyLength = nacl.sign.secretKeyLength

exports.generateKey = async function () { // eslint-disable-line require-await
  return nacl.sign.keyPair()
}

/**
 * 
 * @param {UintAarray} seed seed should be a 32 byte uint8array
 */
exports.generateKeyFromSeed = async function (seed) { // eslint-disable-line require-await
  return nacl.sign.keyPair.fromSeed(seed)
}

/**
 * @param {*} key
 * @param {*} msg
 */
exports.hashAndSign = async function (key, msg) { // eslint-disable-line require-await
  return Buffer.from(nacl.sign.detached(msg, key))
}

/**
 * @param {*} key
 * @param {*} sig
 * @param {*} msg
 */
exports.hashAndVerify = async function (key, sig, msg) { // eslint-disable-line require-await
  return nacl.sign.detached.verify(msg, sig, key)
}
