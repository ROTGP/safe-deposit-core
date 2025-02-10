import { test, expect } from 'vitest'
import sd from './../../src/safeDeposit'
import { alice, bob } from './../../test/data/users'

test('asymmetric encryption for alice and bob', async () => {

    await sd.init()

    const messageTxt = "I'm sorry Alice, the end is near"
    const message: Uint8Array = sd.fromString(messageTxt)

    const bobCiphertext: Uint8Array = sd.asymmetricEncrypt(
        message,
        alice.keyExchangeKeypair.publicKey,
        bob.uuid,
        bob.signingKeypair.secretKey
    )

    const { clearText: aliceClearText, uuid: bobUUID } = sd.asymmetricDecrypt(
        bobCiphertext,
        alice.keyExchangeKeypair.secretKey,
        bob.signingKeypair.publicKey
    )

    expect(sd.toString(aliceClearText)).toEqual(messageTxt)
    expect(bobUUID).toEqual(bob.uuid)
})

test('anon asymmetric encryption for alice and bob', async () => {

    await sd.init()

    const messageTxt = "I'm sorry Alice, the end is near"
    const message: Uint8Array = sd.fromString(messageTxt)

    const ciphertext: Uint8Array = sd.asymmetricEncryptAnon(
        message,
        alice.keyExchangeKeypair.publicKey
    )

    const aliceClearText = sd.asymmetricDecryptAnon(
        ciphertext,
        alice.keyExchangeKeypair.secretKey
    )

    expect(sd.toString(aliceClearText)).toEqual(messageTxt)
})