/**
 * @module libp2p-crypto/aes/cipher-mode
 */
declare module "libp2p-crypto/aes/cipher-mode" { }

/**
 * @module libp2p-crypto/aes/cipher-mode
 */
declare module "libp2p-crypto/aes/cipher-mode" { }

/**
 * @module libp2p-crypto/aes/cipher-browser
 */
declare module "libp2p-crypto/aes/cipher-browser" { }

/**
 * @module libp2p-crypto/aes/ciphers
 */
declare module "libp2p-crypto/aes/ciphers" { }

/**
 * @module libp2p-crypto/aes/index-browser
 */
declare module "libp2p-crypto/aes/index-browser" {
    /**
     * @param {*} key
     * @param {*} iv
     */
    function create(key: any, iv: any): void;
}

/**
 * @module libp2p-crypto/aes
 */
declare module "libp2p-crypto/aes" {
    /**
     * @param {*} key
     * @param {*} iv
     */
    function create(key: any, iv: any): void;
}

/**
 * @module libp2p-crypto/hmac/index-browser
 */
declare module "libp2p-crypto/hmac/index-browser" {
    /**
     * @param {*} hashType
     * @param {*} secret
     */
    function create(hashType: any, secret: any): void;
}

/**
 * @module libp2p-crypto/hmac
 */
declare module "libp2p-crypto/hmac" { }

/**
 * @module libp2p-crypto/hmac/lengths
 */
declare module "libp2p-crypto/hmac/lengths" { }

/**
 * @module libp2p-crypto
 */
declare module "libp2p-crypto" { }

/**
 * @module libp2p-crypto/keys/ecdh-browser
 */
declare module "libp2p-crypto/keys/ecdh-browser" {
    /**
     * @param {*} curve
     */
    function generateEphmeralKeyPair(curve: any): void;
}

/**
 * @module libp2p-crypto/keys/ecdh
 */
declare module "libp2p-crypto/keys/ecdh" {
    /**
     * @param {*} curve
     */
    function generateEphmeralKeyPair(curve: any): void;
}

/**
 * @module libp2p-crypto/keys/ed25519-class
 */
declare module "libp2p-crypto/keys/ed25519-class" {
    /**
     *
     * @param {*} key
     */
    class Ed25519PublicKey {
        constructor(key: any);
        /**
         *
         * @param {*} data
         * @param {*} sig
         */
        verify(data: any, sig: any): void;
        /**
         * Marshal
         * @returns {Buffer}
         */
        marshal(): Buffer;
        /**
         * @type {function}
         * @returns {*}
         */
        bytes: (...params: any[]) => any;
        /**
         *
         * @param {*} key
         * @returns {bool}
         */
        equals(key: any): boolean;
        /**
         * Hash
         * @returns {*}
         */
        hash(): any;
    }
    /**
     *
     * @param {Uint8Array|Buffer} key
     * @param {Uint8Array|Buffer} publicKey
     */
    class Ed25519PrivateKey {
        constructor(key: Uint8Array | Buffer, publicKey: Uint8Array | Buffer);
        /**
         *
         * @param {*} message
         */
        sign(message: any): void;
        /**
         * Public
         *
         * @type {function}
         * @readonly
         */
        readonly public: (...params: any[]) => any;
        /**
         * Marshal
         */
        marshal(): void;
        /**
         * Bytes
         * @type {function}
         * @readonly
         */
        readonly bytes: (...params: any[]) => any;
        /**
         *
         * @param {*} key
         */
        equals(key: any): void;
        /**
         * Hash
         */
        hash(): void;
        /**
         * Gets the ID of the key.
         *
         * The key id is the base58 encoding of the SHA-256 multihash of its public key.
         * The public key is a protobuf encoding containing a type and the DER encoding
         * of the PKCS SubjectPublicKeyInfo.
         *
         * @returns {Promise<String>}
         */
        id(): Promise<String>;
    }
    /**
     *
     * @param {*} bytes
     */
    function unmarshalEd25519PrivateKey(bytes: any): void;
    /**
     *
     * @param {*} bytes
     */
    function unmarshalEd25519PublicKey(bytes: any): void;
    /**
     * Generate key pair
     */
    function generateKeyPair(): void;
    /**
     * Generate key pair from seed
     * @param {*} seed
     */
    function generateKeyPairFromSeed(seed: any): void;
}

/**
 * @module libp2p-crypto/keys/ed25519
 */
declare module "libp2p-crypto/keys/ed25519" {
    /**
     *
     * @param {UintAarray} seed seed should be a 32 byte uint8array
     */
    function generateKeyFromSeed(seed: UintAarray): void;
    /**
     * @param {*} key
     * @param {*} msg
     */
    function hashAndSign(key: any, msg: any): void;
    /**
     * @param {*} key
     * @param {*} sig
     * @param {*} msg
     */
    function hashAndVerify(key: any, sig: any, msg: any): void;
}

/**
 * @module libp2p-crypto/keys/ephemeral-keys
 */
declare module "libp2p-crypto/keys/ephemeral-keys" { }

/**
 * @module libp2p-crypto/keys/ephemeral-keys
 */
declare module "libp2p-crypto/keys/ephemeral-keys" { }

/**
 * @module libp2p-crypto/keys
 */
declare module "libp2p-crypto/keys" {
    /**
     * @type {object}
     */
    var supportedKeys: any;
    /**
     * @type {object}
     */
    var keysPBM: any;
    /**
     * @type {*}
     */
    var keyStretcher: any;
    /**
     * @type {*}
     */
    var generateEphemeralKeyPair: any;
    /**
     * Generates a keypair of the given type and bitsize
     *
     * @param {*} type
     * @param {*} bits
     * @returns {*}
     */
    function generateKeyPair(type: any, bits: any): any;
    /**
     * Generates a keypair of the given type and bitsize
     * seed is a 32 byte uint8array
     *
     * @param {*} type
     * @param {*} seed
     * @param {*} bits
     * @returns {*}
     */
    function generateKeyPairFromSeed(type: any, seed: any, bits: any): any;
    /**
     * Converts a protobuf serialized public key into its
     * representative object
     *
     * @param {*} buf
     * @returns {*}
     */
    function unmarshalPublicKey(buf: any): any;
    /**
     * Converts a public key object into a protobuf serialized public key
     *
     * @param {*} key
     * @param {*} type
     * @returns {*}
     */
    function marshalPublicKey(key: any, type: any): any;
    /**
     * Converts a protobuf serialized private key into its
     * representative object
     *
     * @param {*} buf
     * @return {*}
     */
    function unmarshalPrivateKey(buf: any): any;
    /**
     * Converts a private key object into a protobuf serialized private key
     *
     * @param {*} key
     * @param {*} type
     * @returns {*}
     */
    function marshalPrivateKey(key: any, type: any): any;
    /**
     *
     * @param {*} pem
     * @param {*} password
     * @returns {*}
     */
    function import(pem: any, password: any): any;
}

/**
 * @module libp2p-crypto/keys/key-stretcher
 */
declare module "libp2p-crypto/keys/key-stretcher" {
    /**
     * Generates a set of keys for each party by stretching the shared key.
     * (myIV, theirIV, myCipherKey, theirCipherKey, myMACKey, theirMACKey)
     *
     *
     * @param {*} cipherType
     * @param {*} hash
     * @param {*} secret
     * @returns {Promise<object>}
     */
    function default(cipherType: any, hash: any, secret: any): Promise<object>;
}

/**
 * @module libp2p-crypto/keys/key
 */
declare module "libp2p-crypto/keys/key" { }

/**
 * @module libp2p-crypto/keys/key
 */
declare module "libp2p-crypto/keys/key" { }

/**
 * @module libp2p-crypto/keys/rsa-browser
 */
declare module "libp2p-crypto/keys/rsa-browser" {
    /**
     * @param {*} bits
     * @returns {object}
     */
    function generateKey(bits: any): any;
    /**
     * Takes a jwk key
     *
     * @param {*} key
     * @returns {object}
     */
    function unmarshalPrivateKey(key: any): any;
    /**
     * @param {*} key
     * @param {*} msg
     * @returns {Buffer}
     */
    function hashAndSign(key: any, msg: any): Buffer;
    /**
     * @param {*} key
     * @param {*} sig
     * @param {*} msg
     * @returns {*}
     */
    function hashAndVerify(key: any, sig: any, msg: any): any;
}

/**
 * @module libp2p-crypto/keys/rsa-class
 */
declare module "libp2p-crypto/keys/rsa-class" {
    /**
     * @constructs
     * @param {*} key
     */
    class RsaPublicKey {
        constructor(key: any);
        /**
         * @param {*} data
         * @param {*} sig
         */
        verify(data: any, sig: any): void;
        /**
         * marshal
         */
        marshal(): void;
        /**
         * Get bytes
         * @type {function}
         * @readonly
         * @returns {*}
         */
        readonly bytes: (...params: any[]) => any;
        /**
         *
         * @param {*} bytes
         * @returns {*}
         */
        encrypt(bytes: any): any;
        /**
         *
         * @param {*} key
         * @returns {*}
         */
        equals(key: any): any;
        /**
         * hash
         * @returns {*}
         */
        hash(): any;
    }
    /**
     * @constructs
     * @param {object} key Object of the jwk format
     * @param {Buffer} publicKey Buffer of the spki format
     */
    class RsaPrivateKey {
        constructor(key: any, publicKey: Buffer);
        /**
         * genSecret
         * @returns {*}
         */
        genSecret(): any;
        /**
         * sign
         * @param {*} message
         * @returns {Promise<*>}
         */
        sign(message: any): Promise<any>;
        /**
         * public
         * @type {function}
         * @readonly
         * @returns {module:keys/rsa-class~RsaPublicKey}
         */
        readonly public: (...params: any[]) => any;
        /**
         * marshal
         * @returns {*}
         */
        marshal(): any;
        /**
         * bytes
         * @type {function}
         * @readonly
         * @returns {*}
         */
        readonly bytes: (...params: any[]) => any;
        /**
         *
         * @param {*} key
         * @returns {boolean}
         */
        equals(key: any): boolean;
        /**
         * @returns {Promise<*>}
         */
        hash(): Promise<any>;
        /**
         * Gets the ID of the key.
         *
         * The key id is the base58 encoding of the SHA-256 multihash of its public key.
         * The public key is a protobuf encoding containing a type and the DER encoding
         * of the PKCS SubjectPublicKeyInfo.
         *
         * @returns {Promise<String>}
         */
        id(): Promise<String>;
        /**
         * Exports the key into a password protected PEM format
         *
         * @param {string} password - The password to read the encrypted PEM
         * @param {string} [format] - Defaults to 'pkcs-8'.
         * @returns {KeyInfo}
         */
        export(password: string, format?: string): KeyInfo;
    }
    /**
     *
     * @param {*} bytes
     * @returns {Promise<module:keys/rsa-class~RsaPrivateKey>}
     */
    function unmarshalRsaPrivateKey(bytes: any): Promise<module>;
    /**
     *
     * @param {*} bytes
     * @returns {Promise<module:keys/rsa-class~RsaPublicKey>}
     */
    function unmarshalRsaPublicKey(bytes: any): Promise<module>;
    /**
     *
     * @param {*} jwk
     * @returns {Promise<module:keys/rsa-class~RsaPrivateKey>}
     */
    function fromJwk(jwk: any): Promise<module>;
    /**
     *
     * @param {*} bits
     * @returns {Promise<module:keys/rsa-class~RsaPrivateKey>}
     */
    function generateKeyPair(bits: any): Promise<module>;
}

/**
 * @module libp2p-crypto/keys/rsa-utils
 */
declare module "libp2p-crypto/keys/rsa-utils" {
    /**
     * Convert a PKCS#1 in ASN1 DER format to a JWK key
     *
     * @param {*} bytes
     */
    function pkcs1ToJwk(bytes: any): void;
    /**
     * Convert a JWK key into PKCS#1 in ASN1 DER format
     *
     * @param {*} jwk
     */
    function jwkToPkcs1(jwk: any): void;
    /**
     * Convert a PKCIX in ASN1 DER format to a JWK key
     *
     * @param {*} bytes
     */
    function pkixToJwk(bytes: any): void;
    /**
     * Convert a JWK key to PKCIX in ASN1 DER format
     *
     * @param {*} bytes
     */
    function jwkToPkix(bytes: any): void;
}

/**
 * @module libp2p-crypto/keys/rsa
 */
declare module "libp2p-crypto/keys/rsa" {
    /**
     * @param {*} bits
     */
    function generateKey(bits: any): void;
    /**
     * Takes a jwk key
     * @param {*} key
     */
    function unmarshalPrivateKey(key: any): void;
    /**
     * @param {*} key
     * @param {*} msg
     */
    function hashAndSign(key: any, msg: any): void;
    /**
     * @param {*} key
     * @param {*} sig
     * @param {*} msg
     */
    function hashAndVerify(key: any, sig: any, msg: any): void;
}

/**
 * @module libp2p-crypto/keys/validate-curve-type
 */
declare module "libp2p-crypto/keys/validate-curve-type" { }

/**
 * @module libp2p-crypto/keys/validate-curve-type
 */
declare module "libp2p-crypto/keys/validate-curve-type" { }

/**
 * @module libp2p-crypto/pbkdf2
 */
declare module "libp2p-crypto/pbkdf2" {
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
    function pbkdf2(password: string, salt: string, iterations: number, keySize: number, hash: string): string;
}

/**
 * @module libp2p-crypto/random-bytes
 */
declare module "libp2p-crypto/random-bytes" { }

/**
 * @module libp2p-crypto/random-bytes
 */
declare module "libp2p-crypto/random-bytes" { }

/**
 * @module libp2p-crypto/util
 */
declare module "libp2p-crypto/util" {
    /**
     * Convert a BN.js instance to a base64 encoded string without padding
     * Adapted from https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-C
     *
     * @param {*} bn
     * @param {*} len
     * @returns {BN}
     */
    function toBase64(bn: any, len: any): BN;
    /**
     * Convert a base64 encoded string to a BN.js instance
     * @param {string} str
     * @returns {BN}
     */
    function toBn(str: string): BN;
}

/**
 * @module libp2p-crypto/webcrypto
 */
declare module "libp2p-crypto/webcrypto" {
    /**
     * Check native crypto exists and is enabled (In insecure context `self.crypto`
     * exists but `self.crypto.subtle` does not).
     * @param {*} win
     * @returns {*}
     */
    function get(win: any): any;
}

