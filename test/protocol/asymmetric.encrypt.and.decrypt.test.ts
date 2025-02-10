import { test, expect, beforeEach } from 'vitest'
import sd, { PasswordHashingEffort } from '../../src/safeDeposit'

beforeEach(async () => {
    await sd.init()
})

test('anon asymmetric encryption', async () => {

    const alicePasshphrase = 'alice password'
    const aliceQRCode = sd.generateMasterQRCode(alicePasshphrase, PasswordHashingEffort.interactive)
    const aliceCredentials = sd.generateUserCredentials(alicePasshphrase, aliceQRCode)

    const message = 'Hi Alice, the code you requested is: QTM-2412-XPQA. Best, Bob'
    const anonMessageFromBobToAlice = sd.asymmetricEncryptAnon(
        sd.fromString(message),
        aliceCredentials.keyExchangeKeypair.publicKey
    )

    const clearText = sd.asymmetricDecryptAnon(
        anonMessageFromBobToAlice,
        aliceCredentials.keyExchangeKeypair.secretKey
    )
    expect(message).toEqual(sd.toString(clearText))

    const byte = anonMessageFromBobToAlice[0]
    const badByte = byte === 0 ? 1 : byte - 1
    anonMessageFromBobToAlice[0] = badByte

    try {
        sd.asymmetricDecryptAnon(
            anonMessageFromBobToAlice,
            aliceCredentials.keyExchangeKeypair.secretKey
        )
    } catch (e) {
        expect(e.message).toBe('invalid tag')
    }
})

test('signed asymmetric encryption', async () => {

    const alicePasshphrase = 'alice password'
    const aliceQRCode = sd.generateMasterQRCode(alicePasshphrase, PasswordHashingEffort.interactive)
    const aliceCredentials = sd.generateUserCredentials(alicePasshphrase, aliceQRCode)

    const bobPasshphrase = 'bob password'
    const bobQRCode = sd.generateMasterQRCode(bobPasshphrase, PasswordHashingEffort.interactive)
    const bobCredentials = sd.generateUserCredentials(bobPasshphrase, bobQRCode)

    const message = 'Hi Alice, the code you requested is: QTM-2412-XPQA. Best, Bob'
    const signedMessageFromBobToAlice = sd.asymmetricEncrypt(
        sd.fromString(message),
        aliceCredentials.keyExchangeKeypair.publicKey,
        bobCredentials.uuid,
        bobCredentials.signingKeypair.secretKey
    )

    const clearText = sd.asymmetricDecrypt(
        signedMessageFromBobToAlice,
        aliceCredentials.keyExchangeKeypair.secretKey,
        bobCredentials.signingKeypair.publicKey
    )

    expect(message).toEqual(sd.toString(clearText.clearText))
    expect(bobCredentials.uuid).toEqual(clearText.uuid)

    const byte = signedMessageFromBobToAlice[signedMessageFromBobToAlice.length - 1]
    const badByte = byte === 0 ? 1 : byte - 1
    signedMessageFromBobToAlice[signedMessageFromBobToAlice.length - 1] = badByte

    try {
        sd.asymmetricDecrypt(
            signedMessageFromBobToAlice,
            aliceCredentials.keyExchangeKeypair.secretKey,
            bobCredentials.signingKeypair.publicKey
        )
    } catch (e) {
        expect(e.message).toBe('invalid signature')
    }
})
