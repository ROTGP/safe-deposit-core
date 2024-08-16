import { PasswordHashingEffort } from "./safeDeposit"

/**
 * An Unauthenticated User has provided their
 * credentials and it attempting to authenticate
 */
export type UnauthenticatedUser = {

    // case-insensitive string from 3 to 1000 characters
    alias: string

    // case-sensitive string from 4 to 1000 characters
    passphrase: string

    // numeric string from 4 to 10 digits
    pin: string

    // 58 bytes - wrapped masterKey + metadata
    QRCode: Uint8Array
}

export type UserWithCredentials = UnauthenticatedUser & {

    symmetricKey: Uint8Array

    x25519Keypair: x25519Keypair

    ed25519Keypair: ed25519Keypair
}

export type TestUser = UserWithCredentials & {

    // 32 CSPRNG bytes
    masterKey: Uint8Array

    effort: PasswordHashingEffort
}

export type ed25519Keypair = {

    // 32 bytes
    publicKey: Uint8Array

    // 64 bytes
    privateKey: Uint8Array
}

export type x25519Keypair = {

    // 32 bytes
    publicKey: Uint8Array

    // 64 bytes
    privateKey: Uint8Array
}