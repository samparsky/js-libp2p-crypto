'use strict'

/**
 * @module libp2p-crypto/random-bytes
 */

const randomBytes = require('iso-random-stream/src/random')
const errcode = require('err-code')

/**
 * @param {*} length
 */
module.exports = function (length) {
  if (isNaN(length) || length <= 0) {
    throw errcode(new Error('random bytes length must be a Number bigger than 0'), 'ERR_INVALID_LENGTH')
  }
  return randomBytes(length)
}
