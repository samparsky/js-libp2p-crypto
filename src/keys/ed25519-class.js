/**
 * @module libp2p-crypto/keys/ed25519-class
 */

'use strict'

const multihashing = require('multihashing-async')
const protobuf = require('protons')
const bs58 = require('bs58')
const errcode = require('err-code')

const crypto = require('./ed25519')
const pbm = protobuf(require('./keys.proto'))

/**
 * @class
 */
class Ed25519PublicKey {
  /**
   *
   * @param {*} key
   */
  constructor (key) {
    this._key = ensureKey(key, crypto.publicKeyLength)
  }

  /**
   *
   * @param {*} data
   * @param {*} sig
   */
  async verify (data, sig) { // eslint-disable-line require-await
    return crypto.hashAndVerify(this._key, sig, data)
  }

  /**
   * Marshal
   * @returns {Buffer}
   */
  marshal () {
    return Buffer.from(this._key)
  }
  /**
   * @returns {*}
   */
  get bytes () {
    return pbm.PublicKey.encode({
      Type: pbm.KeyType.Ed25519,
      Data: this.marshal()
    })
  }
/**
 *
 * @param {*} key
 * @returns {bool}
 */
  equals (key) {
    return this.bytes.equals(key.bytes)
  }

  /**
   * Hash
   * @returns {*}
   */
  async hash () { // eslint-disable-line require-await
    return multihashing(this.bytes, 'sha2-256')
  }
}

/**
 * @class
 */
class Ed25519PrivateKey {
  // key       - 64 byte Uint8Array or Buffer containing private key
  // publicKey - 32 byte Uint8Array or Buffer containing public key
  /**
   * 
   * @param {Uint8Array|Buffer} key
   * @param {Uint8Array|Buffer} publicKey
   */
  constructor (key, publicKey) {
    this._key = ensureKey(key, crypto.privateKeyLength)
    this._publicKey = ensureKey(publicKey, crypto.publicKeyLength)
  }
  /**
   *
   * @param {*} message
   */
  async sign (message) { // eslint-disable-line require-await
    return crypto.hashAndSign(this._key, message)
  }
  /**
   * Public
   */
  get public () {
    return new Ed25519PublicKey(this._publicKey)
  }
  /**
   * Marshal
   */
  marshal () {
    return Buffer.concat([Buffer.from(this._key), Buffer.from(this._publicKey)])
  }
  /**
   * Bytes
   */
  get bytes () {
    return pbm.PrivateKey.encode({
      Type: pbm.KeyType.Ed25519,
      Data: this.marshal()
    })
  }
  /**
   *
   * @param {*} key
   */
  equals (key) {
    return this.bytes.equals(key.bytes)
  }
  /**
   * Hash
   */
  async hash () { // eslint-disable-line require-await
    return multihashing(this.bytes, 'sha2-256')
  }

  /**
   * Gets the ID of the key.
   *
   * The key id is the base58 encoding of the SHA-256 multihash of its public key.
   * The public key is a protobuf encoding containing a type and the DER encoding
   * of the PKCS SubjectPublicKeyInfo.
   *
   * @returns {Promise<String>}
   */
  async id () {
    const hash = await this.public.hash()
    return bs58.encode(hash)
  }
}

/**
 *
 * @param {*} bytes
 */
function unmarshalEd25519PrivateKey (bytes) {
  bytes = ensureKey(bytes, crypto.privateKeyLength + crypto.publicKeyLength)
  const privateKeyBytes = bytes.slice(0, crypto.privateKeyLength)
  const publicKeyBytes = bytes.slice(crypto.privateKeyLength, bytes.length)
  return new Ed25519PrivateKey(privateKeyBytes, publicKeyBytes)
}
/**
 *
 * @param {*} bytes
 */
function unmarshalEd25519PublicKey (bytes) {
  bytes = ensureKey(bytes, crypto.publicKeyLength)
  return new Ed25519PublicKey(bytes)
}
/**
 * Generate key pair
 */
async function generateKeyPair () {
  const { secretKey, publicKey } = await crypto.generateKey()
  return new Ed25519PrivateKey(secretKey, publicKey)
}
/**
 * Generate key pair from seed
 * @param {*} seed
 */
async function generateKeyPairFromSeed (seed) {
  const { secretKey, publicKey } = await crypto.generateKeyFromSeed(seed)
  return new Ed25519PrivateKey(secretKey, publicKey)
}

function ensureKey (key, length) {
  if (Buffer.isBuffer(key)) {
    key = new Uint8Array(key)
  }
  if (!(key instanceof Uint8Array) || key.length !== length) {
    throw errcode(new Error('Key must be a Uint8Array or Buffer of length ' + length), 'ERR_INVALID_KEY_TYPE')
  }
  return key
}

module.exports = {
  Ed25519PublicKey,
  Ed25519PrivateKey,
  unmarshalEd25519PrivateKey,
  unmarshalEd25519PublicKey,
  generateKeyPair,
  generateKeyPairFromSeed
}
