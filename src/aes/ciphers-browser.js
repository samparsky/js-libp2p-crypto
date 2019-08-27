/**
 * @module libp2p-crypto/aes/cipher-browser
 */

'use strict'

const crypto = require('browserify-aes')

module.exports = {
  createCipheriv: crypto.createCipheriv,
  createDecipheriv: crypto.createDecipheriv
}
