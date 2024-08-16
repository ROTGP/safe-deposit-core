import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { alice } from '../test/data/users'

test('private symmetric encryption and decryption', async () => {

    await safeDeposit.init()

    const messageTxt: string = 'this is my $upser secre+ Mess@ge'
    const message: Uint8Array = safeDeposit.fromString(messageTxt)

    const ciphertext: Uint8Array = safeDeposit.symmetricEncrypt(
        message,
        alice.symmetricKey
    )

    const cleartext: Uint8Array = safeDeposit.symmetricDecrypt(
        ciphertext,
        alice.symmetricKey
    )

    expect(cleartext).toEqual(message)
    expect(safeDeposit.toString(cleartext)).toEqual(messageTxt)
})