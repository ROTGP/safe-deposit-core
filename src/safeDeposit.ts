
import _sodium from 'libsodium-wrappers-sumo'

import ssh from 'micro-key-producer/ssh.js'

import QRCode, { QRCodeSegment } from 'qrcode'

import jsQR from 'jsqr'

import { xchacha20poly1305 } from '@noble/ciphers/chacha'

import { ml_kem1024 } from '@noble/post-quantum/ml-kem'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa'
import { utf8ToBytes, randomBytes, equalBytes } from '@noble/post-quantum/utils'

import { bytesToHex, hexToBytes, bytesToUtf8 } from '@noble/ciphers/utils';

import { base64 } from '@scure/base'

import * as hkdf from '@noble/hashes/hkdf'
import { sha512 } from '@noble/hashes/sha2'


import {
    SignatureKeypair,
    UserWithCredentials,
    RequestPayload,
    KeyExchangeKeypair,
    EncapsulatedSecret,
    AccountKeyingMaterial,
    DecryptedAsymmetricMessage,
    PassphraseHashSubKeys
} from './types'

import { aeskw } from '@noble/ciphers/aes'
import { blake2b } from '@noble/hashes/blake2b'

const NONCE_LENGTH = 24
const SIGNATURE_LENGTH = 4627

type Sodium = typeof _sodium

// CAUTION - these may NOT be edited
export enum KeyType {

    /**
     * The master key, for generating keying material.
     */
    master = 1,

    /**
     * For generating a ML-DSA keypair, which is used for signing
     * payloads destined for other users.
     */
    signing = 2,

    /**
     * For generating a ML-KEM keypair, which is used for key
     * agreement with other users.
     */
    keyExchange = 3,

    /**
     * For generating a XChaCha20-poly1305 key, which is used for
     * private symmetric encryption.
     */
    symmetric = 4,

    /**
     * For generating a ML-DSA keypair, which is used for signing
     * authenticated API requests.
     */
    apiAuthentication = 5
}

// CAUTION - these may NOT be edited
export enum Version {
    one = 1
}

// CAUTION - these may NOT be edited
export enum PasswordHashingEffort {

    /**
     * Mem: 2 ** 26
     * Ops: 2
     */
    interactive = 1,

    /**
     * Mem: 2 ** 28
     * Ops: 3
     */
    moderate = 2,

    /**
     * Mem: 2 ** 30
     * Ops: 4
     */
    sensitive = 3
}

class SafeDeposit {

    sodium!: Sodium

    public async init() {
        await _sodium.ready
        this.sodium = _sodium
    }

    public subArray(value: Uint8Array, offset: number, length: number = undefined!): Uint8Array {

        return length === undefined ? value.slice(offset) : value.slice(offset, offset + length)
    }

    public isEqual(one: Uint8Array, two: Uint8Array): boolean {
        try {
            return equalBytes(one, two)
        } catch (e) {
            return false
        }
    }

    public toHex(value: Uint8Array): string {
        return bytesToHex(value)
    }

    public fromHex(value: string): Uint8Array {
        return hexToBytes(value)
    }

    public fromString(value: string): Uint8Array {
        return utf8ToBytes(value)
    }

    public toString(value: Uint8Array): string {
        return bytesToUtf8(value)
    }

    public randomBytes(length: number): Uint8Array {
        return randomBytes(length)
    }

    public toBase64(value: Uint8Array): string {
        return base64.encode(value)
    }

    public fromBase64(value: string): Uint8Array {
        return base64.decode(value)
    }

    // encode a (max) 16-bit number into two bytes
    public intToBytes(value: number): Uint8Array {
        if (value >= 65536) {
            throw new Error('Value must be less than 65536')
        }
        return new Uint8Array(new Uint16Array([value]).buffer)
    }

    // decode two bytes into a (max) 16-bit number 
    public bytesToInt(value: Uint8Array): number {
        return (new DataView((new Uint8Array(value)).buffer, 0)).getUint16(0, true)
    }

    // for signatures
    public signatureKeypair(seed: Uint8Array): SignatureKeypair {
        return ml_dsa87.keygen(seed)
    }

    public sign(message: Uint8Array, mySecretKey: Uint8Array): Uint8Array {
        return ml_dsa87.sign(mySecretKey, message)
    }

    public verify(message: Uint8Array, signature: Uint8Array, theirPublicKey: Uint8Array): boolean {
        return ml_dsa87.verify(theirPublicKey, message, signature)
    }

    // seed should be 64 bytes
    public keyExchangeKeypair(seed?: Uint8Array): KeyExchangeKeypair {
        return ml_kem1024.keygen(seed)
    }
    public encapsulate(theirPublicKey: Uint8Array, message?: Uint8Array): EncapsulatedSecret {
        return ml_kem1024.encapsulate(theirPublicKey, message)
    }

    public decapsulate(cipherText: Uint8Array, theirSecretKey: Uint8Array) {
        return ml_kem1024.decapsulate(cipherText, theirSecretKey)
    }

    // keyToWrap length must be in multiples of 16 bytes 
    public wrapKey(keyEncryptionKey: Uint8Array, keyToWrap: Uint8Array): Uint8Array {
        if (keyEncryptionKey.length !== 32) {
            throw new Error('KEK must be 32 bytes')
        }
        return aeskw(keyEncryptionKey).encrypt(keyToWrap)
    }

    public unwrapKey(keyEncryptionKey: Uint8Array, wrappedKey: Uint8Array): Uint8Array {
        if (keyEncryptionKey.length !== 32) {
            throw new Error('KEK must be 32 bytes')
        }
        return aeskw(keyEncryptionKey).decrypt(wrappedKey)
    }

    public symmetricEncrypt(
        data: Uint8Array,
        key: Uint8Array,
        nonce: Uint8Array = undefined!,
        aad: Uint8Array = undefined!
    ) {

        if (nonce === undefined) {
            nonce = this.randomBytes(NONCE_LENGTH)
        }

        if (aad === undefined) {
            aad = Uint8Array.from([])
        }

        const cipher = xchacha20poly1305(key, nonce, aad)

        const cipherText = cipher.encrypt(data)

        const aadLenAsInt = aad.length

        const aadLenAsBytes = this.intToBytes(aadLenAsInt)

        return new Uint8Array([
            ...nonce,
            ...aadLenAsBytes,
            ...(aad ? aad : []),
            ...cipherText
        ])
    }

    public getAADFromCipherText(cipherText: Uint8Array) {

        const nonce = this.subArray(cipherText, 0, NONCE_LENGTH)
        const aadLenAsBytesLen = 2
        const aadLenAsBytes = this.subArray(cipherText, nonce.length, aadLenAsBytesLen)
        const aadLen = this.bytesToInt(aadLenAsBytes)
        return this.subArray(cipherText, nonce.length + aadLenAsBytesLen, aadLen)
    }

    public symmetricDecrypt(
        cipherText: Uint8Array,
        key: Uint8Array
    ) {

        const nonce = this.subArray(cipherText, 0, NONCE_LENGTH)

        const aadLenAsBytesLen = 2

        // the length of the aad, represented as a byte array
        const aadLenAsBytes = this.subArray(cipherText, nonce.length, aadLenAsBytesLen)

        // the length of the aad, represented as an int
        const aadLen = this.bytesToInt(aadLenAsBytes)

        // the actual aad bytes
        const aad = this.subArray(cipherText, nonce.length + aadLenAsBytesLen, aadLen)

        const toDecrypt = this.subArray(cipherText, nonce.length + aadLenAsBytesLen + aadLen)

        const cipher = xchacha20poly1305(key, nonce, aad)

        return cipher.decrypt(toDecrypt)
    }

    public asymmetricEncrypt(
        clearText: Uint8Array,
        theirKeyExchangePublicKey: Uint8Array,
        myUUID: Uint8Array,
        mySecretSigningKey: Uint8Array
    ): Uint8Array {

        const { cipherText, sharedSecret } = this.encapsulate(theirKeyExchangePublicKey)

        const preparedSecret = this.simpleHash(sharedSecret, sharedSecret.length)

        const aad = Uint8Array.from([...myUUID, ...cipherText])

        const encrypted = this.symmetricEncrypt(clearText, preparedSecret, undefined!, aad)

        const signature = this.sign(encrypted, mySecretSigningKey)

        return Uint8Array.from([...encrypted, ...signature])
    }

    public asymmetricDecrypt(
        cipherText: Uint8Array,
        myKeyExchangeSecretKey: Uint8Array,
        theirPublicSigningKey: Uint8Array
    ): DecryptedAsymmetricMessage {

        const signature = this.subArray(cipherText, cipherText.length - SIGNATURE_LENGTH)

        const cipherTextWithoutSignature = this.subArray(cipherText, 0, cipherText.length - SIGNATURE_LENGTH)

        const isValid = this.verify(cipherTextWithoutSignature, signature, theirPublicSigningKey)

        if (isValid !== true) {
            throw new Error('invalid signature')
        }

        const aad = this.getAADFromCipherText(cipherText)

        const theirUUID = this.subArray(aad, 0, 16)

        const mlKemCipherText = this.subArray(aad, 16)

        const sharedKey: Uint8Array = this.decapsulate(mlKemCipherText, myKeyExchangeSecretKey)

        const preparedSecret = this.simpleHash(sharedKey, sharedKey.length)

        return {
            clearText: this.symmetricDecrypt(cipherTextWithoutSignature, preparedSecret),
            uuid: theirUUID
        }
    }

    public asymmetricEncryptAnon(clearText: Uint8Array, theirKeyExchangePublicKey: Uint8Array): Uint8Array {

        const { cipherText, sharedSecret } = this.encapsulate(theirKeyExchangePublicKey)

        const preparedSecret = this.simpleHash(sharedSecret, sharedSecret.length)

        return this.symmetricEncrypt(clearText, preparedSecret, undefined!, cipherText)
    }

    public asymmetricDecryptAnon(cipherText: Uint8Array, myKeyExchangeSecretKey: Uint8Array): Uint8Array {

        const aad = this.getAADFromCipherText(cipherText)

        const sharedKey: Uint8Array = this.decapsulate(aad, myKeyExchangeSecretKey)

        const preparedSecret = this.simpleHash(sharedKey, sharedKey.length)

        return this.symmetricDecrypt(cipherText, preparedSecret)
    }

    public randomAlphaNumeric(length: number): string {

        const keySpace: string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return Array.from(Array(length), () => keySpace[this.sodium.randombytes_uniform(keySpace.length)]).join('')
    }

    // Slow-hash deterministic keying material produced by passphrase, salt, and Argon2ID hashing algorithm
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

    public generateOpenSSHKeyPair() {

        const seed = this.randomBytes(32)
        const key = ssh(seed)

        return {
            private: key.privateKey,
            public: key.publicKey
        }
    }

    public contextFromKeyType(keyType: KeyType): string {
        return KeyType[keyType].substring(0, 8).padEnd(8, '_')
    }

    public deriveKey(
        ikm: Uint8Array,
        length: number,
        keyType: KeyType,
        salt?: Uint8Array
    ) {

        const info = this.fromString(this.contextFromKeyType(keyType))

        return this.deriveKeyBasedKey(ikm, length, info, salt)
    }

    public subkeysFromPassphraseHash(value: Uint8Array): PassphraseHashSubKeys {

        if (!value || value.length !== 64) {
            throw new Error('incorrect passphrase hash length')
        }
        return {
            subkey1: this.subArray(value, 0, 32),
            subkey2: this.subArray(value, 32, 32)
        }
    }

    public deriveKeyBasedKey(
        inputKeyingMaterial: Uint8Array,
        length: number,
        info: Uint8Array,
        salt?: Uint8Array
    ): Uint8Array {

        const prk = hkdf.extract(sha512, inputKeyingMaterial, salt)
        return hkdf.expand(sha512, prk, info, length)
    }

    /**
     * Generates a QR code for the user, which holds
     * their UUID, some metadata, and their encrypted
     * master key.
     *  
     * @param passphrase - the user's passphrase
     * @param effort - how much effort is required for Argon2id hash
     * @param uuidBytes - 16 CSPRNG bytes to uniquely identify the user 
     * @param masterKeyBytes - 32 CSPRNG bytes
     * @param auxiliaryKeyBytes - 16 CSPRNG bytes
     * @returns - the QR code bytes
     */
    public generateMasterQRCode(
        passphrase: string,
        effort: PasswordHashingEffort,
        uuidBytes?: Uint8Array,
        masterKeyBytes?: Uint8Array,
        auxiliaryKeyBytes?: Uint8Array,
    ): Uint8Array {

        const uuid = uuidBytes === undefined ? this.randomBytes(16) : uuidBytes

        const passphraseHash: Uint8Array = this.generatePasswordHash(
            64,
            passphrase,
            uuid,
            effort
        )

        const masterKey = masterKeyBytes === undefined ? this.randomBytes(32) : masterKeyBytes

        const auxiliaryKey = auxiliaryKeyBytes === undefined ? this.randomBytes(16) : auxiliaryKeyBytes

        const passphraseHashSubKeys = this.subkeysFromPassphraseHash(passphraseHash)

        const wrappedMasterKey = new Uint8Array([
            ...uuid,
            ...[Version.one],
            ...[KeyType.master],
            ...[effort],
            ...this.wrapKey(passphraseHashSubKeys.subkey1, Uint8Array.from([...masterKey, ...auxiliaryKey]))
        ])

        const checksum: Uint8Array = this.simpleHash(wrappedMasterKey, 3)

        return new Uint8Array([
            ...wrappedMasterKey,
            ...checksum
        ])
    }

    public extractAccountKeyingMaterial(
        passphrase: string,
        wrappedMasterKey: Uint8Array
    ): AccountKeyingMaterial {

        const checksum: Uint8Array = this.simpleHash(this.subArray(wrappedMasterKey, 0, 75), 3)

        if (!this.isEqual(this.subArray(wrappedMasterKey, 75, 3), checksum)) {
            throw new Error('Incorrect checksum')
        }

        const version: number = wrappedMasterKey[16]

        if (version !== Version.one) {
            throw new Error('Incorrect version')
        }

        const keyType: number = wrappedMasterKey[17]

        if (keyType !== KeyType.master) {
            throw new Error('Incorrect key type')
        }

        const uuid = this.subArray(wrappedMasterKey, 0, 16)

        const effort = wrappedMasterKey[18]

        if (!Object.values(PasswordHashingEffort).includes(effort)) {
            throw new Error('Unrecognized password hashing effort')
        }

        const passphraseHash: Uint8Array = this.generatePasswordHash(
            64,
            passphrase,
            uuid,
            wrappedMasterKey[18]
        )

        const passphraseHashSubKeys = this.subkeysFromPassphraseHash(passphraseHash)

        const unwrappedMasterKey = this.unwrapKey(
            passphraseHashSubKeys.subkey1,
            this.subArray(wrappedMasterKey, 19, 56)
        )

        const masterKey = this.subArray(unwrappedMasterKey, 0, 32)
        const auxiliaryKey = this.subArray(unwrappedMasterKey, 32, 16)

        return {
            uuid,
            masterKey,
            auxiliaryKey,
            effort,
            passphraseHash
        }
    }

    public keypairHash(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
        return sha512(Uint8Array.from([...secretKey, ...publicKey]))
    }

    public generateUserCredentials(passphrase: string, QRCode: Uint8Array): UserWithCredentials {

        const accountKeyingMaterial: AccountKeyingMaterial = this.extractAccountKeyingMaterial(passphrase, QRCode)

        const masterKey: Uint8Array = accountKeyingMaterial.masterKey
        const auxiliaryKey: Uint8Array = accountKeyingMaterial.auxiliaryKey
        const passphraseHash: Uint8Array = accountKeyingMaterial.passphraseHash

        const symmetricKey: Uint8Array = this.deriveKey(
            masterKey,
            32,
            KeyType.symmetric,
            this.subArray(auxiliaryKey, 0, 4)
        )

        const keyExchangeKeypairSeed: Uint8Array = this.deriveKey(
            masterKey,
            64,
            KeyType.keyExchange,
            this.subArray(auxiliaryKey, 4, 4)

        )
        const keyExchangeKeypair = this.keyExchangeKeypair(keyExchangeKeypairSeed)
        const keyExchangeKeypairHash = this.keypairHash(keyExchangeKeypair.secretKey, keyExchangeKeypair.publicKey)

        const signingKeypairSeed: Uint8Array = this.deriveKey(
            masterKey,
            32,
            KeyType.signing,
            this.subArray(auxiliaryKey, 8, 4)
        )

        const signingKeypair = this.signatureKeypair(signingKeypairSeed)
        const signingKeypairHash = this.keypairHash(signingKeypair.secretKey, signingKeypair.publicKey)

        const passphraseHashSubKeys = this.subkeysFromPassphraseHash(passphraseHash)

        const apiAuthKeypairSeed: Uint8Array = this.deriveKey(
            passphraseHashSubKeys.subkey2,
            32,
            KeyType.apiAuthentication,
            this.subArray(auxiliaryKey, 12, 4)
        )

        const apiAuthKeypair = this.signatureKeypair(apiAuthKeypairSeed)
        const apiAuthKeypairHash = this.keypairHash(apiAuthKeypair.secretKey, apiAuthKeypair.publicKey)

        return {
            passphrase: passphrase,
            QRCode: QRCode,
            ...accountKeyingMaterial,
            symmetricKey,

            keyExchangeKeypairSeed,
            keyExchangeKeypair,
            keyExchangeKeypairHash,

            signingKeypairSeed,
            signingKeypair,
            signingKeypairHash,

            apiAuthKeypairSeed,
            apiAuthKeypair,
            apiAuthKeypairHash
        }
    }

    public simpleHash(value: Uint8Array, length: number, key?: Uint8Array): Uint8Array {
        return blake2b(value, { dkLen: length, key })
    }

    public buildRequestPayload(
        uuid: Uint8Array,
        timestamp: number,
        nonce: Uint8Array,
        absoluteUrl: string,
        requestMethod: string,
        requestPayload: RequestPayload
    ): Uint8Array {

        const stripTrailingSlash = (value: string) => value.endsWith('/') ? value.slice(0, -1) : value

        const sortObjectKeys = (obj: RequestPayload) => {
            return Object.keys(obj).sort().reduce((result: RequestPayload, key) => {
                result[key] = obj[key]
                return result
            }, {})
        }

        return safeDeposit.fromString([
            this.toHex(uuid),
            `${timestamp}`,
            this.toBase64(nonce),
            stripTrailingSlash(absoluteUrl.trim().toLowerCase()),
            requestMethod.trim().toUpperCase(),
            JSON.stringify(sortObjectKeys(requestPayload))
        ].join('|'))
    }

    public signRequest(
        uuid: Uint8Array,
        timestamp: number,
        nonce: Uint8Array,
        absoluteUrl: string,
        requestMethod: string,
        requestPayload: RequestPayload,
        secretKey: Uint8Array
    ): Uint8Array {

        if (nonce.length !== 32) {
            throw new Error('Invalid nonce length')
        }

        return this.sign(
            this.buildRequestPayload(
                uuid,
                timestamp,
                nonce,
                absoluteUrl,
                requestMethod,
                requestPayload
            ),
            secretKey
        )
    }

    public verifyRequestSignature(
        uuid: Uint8Array,
        timestamp: number,
        nonce: Uint8Array,
        absoluteUrl: string,
        requestMethod: string,
        requestPayload: RequestPayload,
        publicKey: Uint8Array,
        signature: Uint8Array
    ): boolean {

        return this.verify(
            this.buildRequestPayload(
                uuid,
                timestamp,
                nonce,
                absoluteUrl,
                requestMethod,
                requestPayload
            ),
            signature,
            publicKey
        )
    }

    public prettyUser(user: UserWithCredentials) {

        const format = (value: Uint8Array): string => {
            return `${this.toHex(this.subArray(value, 0, 80))}${value.length > 80 ? '...' : '   '} (${value.length} bytes)`
        }
        const result = {

            uuid: format(user.uuid),

            passphrase: user.passphrase,

            effort: PasswordHashingEffort[user.effort],

            masterKey: format(user.masterKey),

            auxiliaryKey: format(user.auxiliaryKey),

            QRCode: format(user.QRCode),

            symmetricKey: format(user.symmetricKey),

            keyExchangeKeypairSeed: format(user.keyExchangeKeypairSeed),
            // keyExchangeKeypairSecretKey: format(user.keyExchangeKeypair.secretKey),
            // keyExchangeKeypairPublicKey: format(user.keyExchangeKeypair.publicKey),
            // keyExchangeKeypairHash: format(user.keyExchangeKeypairHash),

            signingKeypairSecretSeed: format(user.signingKeypairSeed),
            // signingKeypairSecretKey: format(user.signingKeypair.secretKey),
            // signingKeypairPublicKey: format(user.signingKeypair.publicKey),
            // signingKeypairHash: format(user.signingKeypairHash),

            apiAuthKeypairSeed: format(user.apiAuthKeypairSeed),
            // apiAuthKeypairSecretKey: format(user.apiAuthKeypair.secretKey),
            // apiAuthKeypairPublicKey: format(user.apiAuthKeypair.publicKey),
            // apiAuthKeypairHash: format(user.apiAuthKeypairHash),
        }
        console.log('user', user)
        console.table(result)
    }

    public updateQRCode(oldPassphrase: string, oldQRCode: Uint8Array, newPassphrase: string, newEffort: PasswordHashingEffort): Uint8Array {

        const uuid = this.subArray(oldQRCode, 0, 16)

        const accountKeyingMaterial: AccountKeyingMaterial = this.extractAccountKeyingMaterial(oldPassphrase, oldQRCode)

        const masterKey: Uint8Array = accountKeyingMaterial.masterKey

        const auxiliaryKey: Uint8Array = accountKeyingMaterial.auxiliaryKey

        return this.generateMasterQRCode(newPassphrase, newEffort, uuid, masterKey, auxiliaryKey)
    }

    public bytesToCanvas(bytes: Uint8Array, canvasId: string, size: number) {

        const segments: QRCodeSegment[] = [{ data: bytes, mode: 'byte' }]

        QRCode.toCanvas(
            document.getElementById(canvasId),
            segments,
            {
                width: size,
                errorCorrectionLevel: 'low'

            })
    }

    public async bytesToImg(bytes: Uint8Array, size: number): Promise<HTMLImageElement> {

        const segments: QRCodeSegment[] = [{ data: bytes, mode: 'byte' }]

        const dataUrl = await QRCode.toDataURL(
            segments,
            {
                width: size,
                errorCorrectionLevel: 'low'
            })

        const img: HTMLImageElement = document.createElement('img')
        img.src = dataUrl
        img.width = size
        img.height = size
        return img
    }

    public canvasToBytes(canvasId: string): Uint8Array | undefined {

        const canvas = document.getElementById(canvasId) as HTMLCanvasElement

        const ctx = canvas.getContext('2d')

        if (!ctx) {
            return undefined
        }

        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height).data

        let code: any

        try {
            code = jsQR(imageData, canvas.width, canvas.height)?.binaryData
            return code ? Uint8Array.from(code) : undefined

        } catch (e) {
            return undefined
        }
    }
}

const safeDeposit = new SafeDeposit()

export default safeDeposit