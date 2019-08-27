/**
 * Computes the Password-Based Key Derivation Function 2.
 *
 * @param {string} password
 * @param {string} salt
 * @param {number} iterations
 * @param {number} keySize (in bytes)
 * @param {string} hash - The hash name ('sha1', 'sha2-512, ...)
 * @returns {string} - A new password
 */
declare function pbkdf2(password: string, salt: string, iterations: number, keySize: number, hash: string): string;

