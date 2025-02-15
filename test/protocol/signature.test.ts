import { test, expect } from 'vitest'
import sd from './../../src/safeDeposit'
import { alice } from './../../test/data/users'
import { UserWithCredentials } from './../../src/types'

test('message signing for alice', async () => {

    const userWithCredentials: UserWithCredentials = await sd.generateUserCredentials(alice.passphrase, alice.QRCode)

    const message = sd.fromString('log-me-in')

    const tamperedMessage = sd.fromString('log-me-iN')

    const signature: Uint8Array = sd.sign(message, userWithCredentials.signingKeypair.secretKey)

    const expectedSignatureHash = sd.fromHex('1a0829a077885d710fbd3c6d928db31d363aa887798c1b4d9ac7a2a2fdec9ed8')

    expect(sd.simpleHash(signature, 32)).toEqual(expectedSignatureHash)

    const valid = sd.verify(message, signature, userWithCredentials.signingKeypair.publicKey)

    expect(valid).toBe(true)

    const tamperedValid = sd.verify(tamperedMessage, signature, userWithCredentials.signingKeypair.publicKey)

    expect(tamperedValid).toBe(false)
})