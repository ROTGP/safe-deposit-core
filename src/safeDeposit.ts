import _sodium, { memcmp } from 'libsodium-wrappers-sumo'
import { ed25519Keypair, x25519Keypair, UserWithCredentials } from './types'

type Sodium = typeof _sodium

export enum KeyType {
    master,
    ed25519,
    x25519,
    wrapAuthentication,
    wrapEncryption,
    symmetric
}

export enum PasswordHashingEffort {
    interactive,
    moderate,
    sensitive
}

class SafeDeposit {

    sodium!: Sodium

    sshpk!: any

    public async init() {

        await _sodium.ready
        this.sodium = _sodium
        this.sshpk = require('sshpk')
    }

    public randomBytes(length: number): Uint8Array {
        return this.sodium.randombytes_buf(length)
    }

    // for signatures
    public ed25519Keypair(seed: Uint8Array): ed25519Keypair {
        return this.sodium.crypto_sign_seed_keypair(
            seed
        )
    }

    public sign(message: Uint8Array, myPrivateKey: Uint8Array): Uint8Array {
        return this.sodium.crypto_sign_detached(message, myPrivateKey)
    }

    public verify(message: Uint8Array, signature: Uint8Array, theirPublicKey: Uint8Array): boolean {
        return this.sodium.crypto_sign_verify_detached(signature, message, theirPublicKey)
    }

    // public and private keypair generation for generating shared
    // x25519 keys
    public x25519Keypair(seed?: Uint8Array): x25519Keypair {
        return seed ? this.sodium.crypto_box_seed_keypair(
            seed
        ) : this.sodium.crypto_box_keypair()
    }

    // x25519 shared key generation
    public x25519SharedKey(myPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
        return this.sodium.crypto_scalarmult(
            myPrivateKey,
            theirPublicKey
        )
    }

    public asymmetricEncrypt(message: Uint8Array, myPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {

        const sharedKey: Uint8Array = this.x25519SharedKey(myPrivateKey, theirPublicKey)

        return this.symmetricEncrypt(message, sharedKey)
    }

    public asymmetricDecrypt(ciphertext: Uint8Array, myPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {

        const sharedKey: Uint8Array = this.x25519SharedKey(myPrivateKey, theirPublicKey)

        return this.symmetricDecrypt(ciphertext, sharedKey)
    }

    public asymmetricEncryptAnon(message: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {

        const myEphemeralKeypair = this.x25519Keypair()

        const sharedKey: Uint8Array = this.x25519SharedKey(myEphemeralKeypair.privateKey, theirPublicKey)

        const ciphertext = this.symmetricEncrypt(message, sharedKey)
        return new Uint8Array([...myEphemeralKeypair.publicKey, ...ciphertext])
    }

    public asymmetricDecryptAnon(ciphertext: Uint8Array, myPrivateKey: Uint8Array): Uint8Array {

        const theirPublicKey = this.subArray(ciphertext, 0, 32)

        const sharedKey: Uint8Array = this.x25519SharedKey(myPrivateKey, theirPublicKey)

        return this.symmetricDecrypt(this.subArray(ciphertext, 32), sharedKey)
    }

    public randomAlphaNumeric(length: number): string {

        const keySpace: string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return Array.from(Array(length), () => keySpace[this.sodium.randombytes_uniform(keySpace.length)]).join('')
    }

    // slow-hash deterministic keying material produced by
    // passphrase, salt, and hasing Argon2ID algorithm
    public generatePasswordHash(length: number, passphrase: string, salt: Uint8Array, effort: PasswordHashingEffort): Uint8Array {

        const opsLimit = effort === PasswordHashingEffort.interactive ? this.sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
            : (effort === PasswordHashingEffort.moderate ?
                this.sodium.crypto_pwhash_OPSLIMIT_MODERATE
                : this.sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE)

        const memLimit = effort === PasswordHashingEffort.interactive ? this.sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
            : (effort === PasswordHashingEffort.moderate ?
                this.sodium.crypto_pwhash_MEMLIMIT_MODERATE
                : this.sodium.crypto_pwhash_MEMLIMIT_SENSITIVE)

        return this.sodium.crypto_pwhash(
            length,
            this.sodium.from_string(passphrase),
            salt,
            opsLimit,
            memLimit,
            this.sodium.crypto_pwhash_ALG_ARGON2ID13
        )
    }

    // https://github.com/TritonDataCenter/node-sshpk
    public generateOpenSSHKeyPair() {
        const privateKey = this.sshpk.generatePrivateKey('ed25519')
        const publicKey = privateKey.toPublic()
        return {
            private: privateKey.toString(),
            public: publicKey.toString()
        }
    }

    public contextFromKeyType(keyType: KeyType) {
        return KeyType[keyType].substring(0, 8).padEnd(8, '_')
    }

    public deriveKey(inputKeyingMaterial: Uint8Array, length: number, keyType: KeyType): Uint8Array {

        const ctx: string = this.contextFromKeyType(keyType)

        return this.sodium.crypto_kdf_derive_from_key(length, Number(keyType), ctx, inputKeyingMaterial)
    }

    public simpleHash(length: number, value: string): Uint8Array {
        return this.sodium.crypto_generichash(
            length,
            this.sodium.from_string(value)
        )
    }


    // simple xchacha20 stream encryption/description with no authentication tag
    public simpleStream(value: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
        return this.sodium.crypto_stream_xchacha20_xor(value, nonce, key)
    }

    public authenticatedSymmetricStreamEncrypt(message: Uint8Array, additionalData: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
        return this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, additionalData, null, nonce, key)
    }

    public authenticatedSymmetricStreamDescrypt(ciphertext: Uint8Array, additionalData: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
        return this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, additionalData, nonce, key)
    }

    // https://security.stackexchange.com/questions/266915/how-to-use-pynacl-libsodium-for-key-wrap-key-encapsulation
    public generateMasterQRCode(alias: string, passphrase: string, pin: string, effort: PasswordHashingEffort, masterKeyBytes?: Uint8Array): Uint8Array {

        const aliasHash = this.simpleHash(16, alias + pin)

        const passphraseHash: Uint8Array = this.generatePasswordHash(
            32,
            passphrase,
            aliasHash,
            effort
        )

        const masterKey = masterKeyBytes === undefined ? this.randomBytes(32) : masterKeyBytes

        const authenticationKey = this.deriveKey(passphraseHash, 32, KeyType.wrapAuthentication)

        const encryptionKey = this.deriveKey(passphraseHash, 32, KeyType.wrapEncryption)

        const authTag = this.sodium.crypto_generichash(32, masterKey, authenticationKey)

        const wrappedMasterKey = new Uint8Array([
            ...[KeyType.master],
            ...[effort],
            ...authTag,
            ...this.simpleStream(masterKey, this.subArray(authTag, 0, 24), encryptionKey)
        ])

        const checksum: Uint8Array = this.sodium.crypto_generichash(4, wrappedMasterKey)

        return new Uint8Array([
            ...wrappedMasterKey,
            ...checksum
        ])
    }

    public generateCredentials(alias: string, passphrase: string, pin: string, QRCode: Uint8Array): UserWithCredentials {

        const masterKey: Uint8Array = this.extractMasterKeyFromQRCode(alias, passphrase, pin, QRCode)

        const symmetricKey: Uint8Array = this.deriveKey(masterKey, 32, KeyType.symmetric)

        const ed25519Seed: Uint8Array = this.deriveKey(masterKey, 32, KeyType.ed25519)
        const ed25519Keypair = this.ed25519Keypair(ed25519Seed)

        const x25519Seed: Uint8Array = this.deriveKey(masterKey, 32, KeyType.x25519)
        const x25519Keypair = this.x25519Keypair(x25519Seed)

        return {
            alias: alias,
            passphrase: passphrase,
            pin: pin,
            QRCode: QRCode,
            symmetricKey: symmetricKey,
            ed25519Keypair: ed25519Keypair,
            x25519Keypair: x25519Keypair
        }
    }

    public extractMasterKeyFromQRCode(alias: string, passphrase: string, pin: string, wrappedMasterKey: Uint8Array): Uint8Array {

        const checksum: Uint8Array = this.sodium.crypto_generichash(4, this.subArray(wrappedMasterKey, 0, 66))
        if (!memcmp(this.subArray(wrappedMasterKey, 66, 4), checksum)) {
            throw new Error('Incorrect checksum')
        }

        const keyType: number = wrappedMasterKey[0]

        if (keyType !== KeyType.master) {
            throw new Error('Incorrect key type')
        }

        const aliasHash = this.simpleHash(16, alias + pin)

        const passphraseHash: Uint8Array = this.generatePasswordHash(
            32,
            passphrase,
            aliasHash,
            wrappedMasterKey[1]
        )

        const authenticationKey = this.deriveKey(passphraseHash, 32, KeyType.wrapAuthentication)

        const encryptionKey = this.deriveKey(passphraseHash, 32, KeyType.wrapEncryption)

        const unwrappedMasterKey = this.simpleStream(
            this.subArray(wrappedMasterKey, 34, 32),
            this.subArray(wrappedMasterKey, 2, 24),
            encryptionKey
        )

        const authTag = this.sodium.crypto_generichash(32, unwrappedMasterKey, authenticationKey)
        if (!this.isEqual(authTag, this.subArray(wrappedMasterKey, 2, 32))) {
            throw new Error('Key authentication failed - incorrect credentials')
        }

        return unwrappedMasterKey
    }

    public symmetricEncrypt(message: Uint8Array, key: Uint8Array, nonce: Uint8Array = this.randomBytes(24)) {

        const ciphertext: Uint8Array = this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, null, null, nonce, key)
        return new Uint8Array([...nonce, ...ciphertext])
    }

    public symmetricDecrypt(ciphertext: Uint8Array, key: Uint8Array) {

        return this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null,
            this.subArray(ciphertext, 24),
            null,
            this.subArray(ciphertext, 0, 24),
            key
        )
    }

    public subArray(value: Uint8Array, offset: number, length: number = undefined!): Uint8Array {

        return length === undefined ? value.slice(offset) : value.slice(offset, offset + length)
    }

    public toHex(value: Uint8Array): string {
        return this.sodium.to_hex(value)
    }

    public fromHex(value: string): Uint8Array {
        return this.sodium.from_hex(value)
    }

    public toBase64(value: Uint8Array): string {
        return this.sodium.to_base64(value)
    }

    public fromBase64(value: string): Uint8Array {
        return this.sodium.from_base64(value)
    }

    public isEqual(one: Uint8Array, two: Uint8Array): boolean {
        try {
            return this.sodium.memcmp(one, two)
        } catch (e) {
            return false
        }
    }

    public fromString(value: string): Uint8Array {
        return this.sodium.from_string(value)
    }

    public toString(value: Uint8Array): string {
        return this.sodium.to_string(value)
    }
}

const safeDeposit = new SafeDeposit()

export default safeDeposit