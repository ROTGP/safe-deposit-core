import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { alice, bob } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('shared key for alice and bob', async () => {

    await safeDeposit.init()

    const aliceSharedKey = safeDeposit.x25519SharedKey(
        alice.x25519Keypair.privateKey,
        bob.x25519Keypair.publicKey
    )

    const bobSharedKey = safeDeposit.x25519SharedKey(
        bob.x25519Keypair.privateKey,
        alice.x25519Keypair.publicKey
    )

    expect(aliceSharedKey).toEqual(bobSharedKey)
    expect(aliceSharedKey.length).toBe(32)
})

test('shared encryption for alice and bob', async () => {

    await safeDeposit.init()

    const messageTxt = "I'm sorry Bob, the end is near"
    const message: Uint8Array = safeDeposit.fromString(messageTxt)

    const aliceCiphertext: Uint8Array = safeDeposit.asymmetricEncrypt(
        message,
        alice.x25519Keypair.privateKey,
        bob.x25519Keypair.publicKey
    )

    const bobCleartext: Uint8Array = safeDeposit.asymmetricDecrypt(
        aliceCiphertext,
        bob.x25519Keypair.privateKey,
        alice.x25519Keypair.publicKey
    )

    expect(safeDeposit.toString(bobCleartext)).toEqual(messageTxt)

    const bobCiphertext: Uint8Array = safeDeposit.asymmetricEncrypt(
        message,
        bob.x25519Keypair.privateKey,
        alice.x25519Keypair.publicKey
    )

    const aliceCleartext: Uint8Array = safeDeposit.asymmetricDecrypt(
        bobCiphertext,
        alice.x25519Keypair.privateKey,
        bob.x25519Keypair.publicKey
    )

    expect(aliceCleartext).toEqual(message)
    expect(safeDeposit.toString(aliceCleartext)).toEqual(messageTxt)
})

test('anon asymmetric encryption and decryption', async () => {

    await safeDeposit.init()

    const messageTxt: string = 'this is my $upser secre+ Mess@ge'
    const message: Uint8Array = safeDeposit.fromString(messageTxt)

    const ciphertext: Uint8Array = safeDeposit.asymmetricEncryptAnon(
        message,
        alice.x25519Keypair.publicKey
    )

    const cleartext: Uint8Array = safeDeposit.asymmetricDecryptAnon(
        ciphertext,
        alice.x25519Keypair.privateKey
    )

    expect(cleartext).toEqual(message)
    expect(safeDeposit.toString(cleartext)).toEqual(messageTxt)
})