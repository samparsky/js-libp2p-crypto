/**
 * @module libp2p-crypto/aes/ciphers
 */

'use strict'

const crypto = require('crypto')

module.exports = {
  createCipheriv: crypto.createCipheriv,
  createDecipheriv: crypto.createDecipheriv
}
