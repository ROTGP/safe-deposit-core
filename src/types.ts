import safeDeposit, { PasswordHashingEffort } from './safeDeposit'

/**
 * An Unauthenticated User has provided their
 * credentials and it attempting to authenticate
 */
export type UnauthenticatedUser = {

    // case-sensitive string from 4 to 1000 characters
    passphrase: string

    // 78 bytes - wrapped masterKey + metadata
    QRCode: Uint8Array
}

/**
 * Includes UUID and basic keying material extracted from QR Code
 */
export type AccountKeyingMaterial = {

    // 16 bytes
    uuid: Uint8Array

    // 32 bytes
    masterKey: Uint8Array

    // 16 bytes
    auxiliaryKey: Uint8Array

    effort: PasswordHashingEffort

    // 64 bytes
    passphraseHash: Uint8Array
}

export type UserWithCredentials = UnauthenticatedUser & AccountKeyingMaterial & {

    // 32 bytes
    symmetricKey: Uint8Array

    keyExchangeKeypairSeed: Uint8Array
    keyExchangeKeypair: KeyExchangeKeypair
    keyExchangeKeypairHash: Uint8Array

    signingKeypairSeed: Uint8Array
    signingKeypair: SignatureKeypair
    signingKeypairHash: Uint8Array

    apiAuthKeypairSeed: Uint8Array
    apiAuthKeypair: SignatureKeypair
    apiAuthKeypairHash: Uint8Array
}


export class TestUser {

    private _uuid: string
    private _passphrase: string
    private _effort: number
    private _masterKey: string
    private _auxiliaryKey: string
    private _QRCode: string
    private _symmetricKey: string
    private _keyExchangeKeypairSeed: string
    private _signingKeypairSeed: string
    private _apiAuthKeypairSeed: string
    private _emailAddresses: string[]

    constructor(
        uuid: string,
        passphrase: string,
        effort: number,
        masterKey: string,
        auxiliaryKey: string,
        QRCode: string,
        symmetricKey: string,
        keyExchangeKeypairSeed: string,
        signingKeypairSeed: string,
        apiAuthKeypairSeed: string,
        emailAddresses: string[]
    ) {
        this._uuid = uuid
        this._passphrase = passphrase
        this._effort = effort
        this._masterKey = masterKey
        this._auxiliaryKey = auxiliaryKey
        this._QRCode = QRCode
        this._symmetricKey = symmetricKey
        this._keyExchangeKeypairSeed = keyExchangeKeypairSeed
        this._signingKeypairSeed = signingKeypairSeed
        this._apiAuthKeypairSeed = apiAuthKeypairSeed
        this._emailAddresses = emailAddresses
    }

    public fromHex(value: string): Uint8Array {
        return safeDeposit.fromHex(value)
    }

    public get uuid(): Uint8Array {
        return this.fromHex(this._uuid)
    }

    public get passphrase(): string {
        return this._passphrase
    }

    public get effort(): PasswordHashingEffort {
        return this._effort
    }

    public get masterKey(): Uint8Array {
        return this.fromHex(this._masterKey)
    }

    public get auxiliaryKey(): Uint8Array {
        return this.fromHex(this._auxiliaryKey)
    }

    public get QRCode(): Uint8Array {
        return this.fromHex(this._QRCode)
    }

    public get symmetricKey(): Uint8Array {
        return this.fromHex(this._symmetricKey)
    }

    public get keyExchangeKeypair(): KeyExchangeKeypair {
        return safeDeposit.keyExchangeKeypair(this.fromHex(this._keyExchangeKeypairSeed))
    }

    public get signingKeypair(): SignatureKeypair {
        return safeDeposit.signatureKeypair(this.fromHex(this._signingKeypairSeed))
    }

    public get apiAuthKeypair(): SignatureKeypair {
        return safeDeposit.signatureKeypair(this.fromHex(this._apiAuthKeypairSeed))
    }

    public get emailAddresses(): string[] {
        return this._emailAddresses
    }
}

export type SignatureKeypair = {

    // 4896 bytes
    secretKey: Uint8Array

    // 2592 bytes
    publicKey: Uint8Array
}

export type KeyExchangeKeypair = {

    // 3168 bytes
    secretKey: Uint8Array

    // 1568 bytes
    publicKey: Uint8Array
}

export type EncapsulatedSecret = {

    // 1568 bytes
    cipherText: Uint8Array

    // 32 bytes
    sharedSecret: Uint8Array
}

export type ApiAuthKeypair = {

    // 32 bytes
    publicKey: Uint8Array

    // 64 bytes
    privateKey: Uint8Array
}

export type RequestPayload = {
    [key: string]: any
}

export type DecryptedAsymmetricMessage = {
    clearText: Uint8Array,
    uuid: Uint8Array
}

export type PassphraseHashSubKeys = {

    // 32 bytes
    subkey1: Uint8Array

    // 32 bytes
    subkey2: Uint8Array
}