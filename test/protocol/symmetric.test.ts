import { test, expect } from 'vitest'
import sd from './../../src/safeDeposit'
import { alice } from './../../test/data/users'

test('private symmetric encryption and decryption with fixed nonce', async () => {

    await sd.init()

    const messageTxt: string = 'this is my $upser secre+ Mess@ge'
    const message: Uint8Array = sd.fromString(messageTxt)

    const nonce = sd.fromHex('3cee1bca002ae6bed3bf29f9aad850ffec59290f2dfda706')

    const ciphertext: Uint8Array = sd.symmetricEncrypt(
        message,
        alice.symmetricKey,
        nonce
    )

    expect(ciphertext).toEqual(sd.fromHex('3cee1bca002ae6bed3bf29f9aad850ffec59290f2dfda7060000dcb2d37a8b5bfe6d49a48c462bb7a6789060cf5a0bccef2d4651037c6371935dae9615d8f40cdd28ae1c97de64b27ce4'))

    const cleartext: Uint8Array = sd.symmetricDecrypt(
        ciphertext,
        alice.symmetricKey
    )

    expect(cleartext).toEqual(message)
    expect(sd.toString(cleartext)).toEqual(messageTxt)
})

test('private symmetric encryption and decryption with generated nonce', async () => {

    await sd.init()

    const messageTxt: string = 'Some other message'
    const message: Uint8Array = sd.fromString(messageTxt)

    const ciphertext: Uint8Array = sd.symmetricEncrypt(
        message,
        alice.symmetricKey
    )

    const cleartext: Uint8Array = sd.symmetricDecrypt(
        ciphertext,
        alice.symmetricKey
    )

    expect(cleartext).toEqual(message)
    expect(sd.toString(cleartext)).toEqual(messageTxt)
})