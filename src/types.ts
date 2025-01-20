import { PasswordHashingEffort } from "./safeDeposit"

/**
 * An Unauthenticated User has provided their
 * credentials and it attempting to authenticate
 */
export type UnauthenticatedUser = {

    // 5 bytes CSPRNG bytes
    uuid: Uint8Array

    // case-sensitive string from 4 to 1000 characters
    passphrase: string

    // 58 bytes - wrapped masterKey + metadata
    QRCode: Uint8Array
}

export type UserWithCredentialsAndMasterKey = UserWithCredentials & {

    masterKey: Uint8Array
}

export type UserWithCredentials = UnauthenticatedUser & {

    symmetricKey: Uint8Array

    x25519Keypair: x25519Keypair

    ed25519Keypair: ed25519Keypair

    apiAuthKeypair: ed25519Keypair
}

export type TestUser = UserWithCredentials & {

    // 32 CSPRNG bytes
    masterKey: Uint8Array

    effort: PasswordHashingEffort

    emailAddresses: string[]
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

export type ApiAuthKeypair = {

    // 32 bytes
    publicKey: Uint8Array

    // 64 bytes
    privateKey: Uint8Array
}

export type RequestPayload = {
    [key: string]: any
}

export type MasterKeyAndApiAuthKeypair = {
    apiAuthKeypair: ApiAuthKeypair,
    masterKey: Uint8Array
}