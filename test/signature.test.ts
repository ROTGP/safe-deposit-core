import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { alice } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('message signing for alice', async () => {

    await safeDeposit.init()

    const userWithCredentials: UserWithCredentials = safeDeposit.generateCredentials(alice.alias, alice.passphrase, alice.pin, alice.QRCode)

    const message = safeDeposit.fromString('log-me-in')

    const tamperedMessage = safeDeposit.fromString('log-me-iN')

    const signature: Uint8Array = safeDeposit.sign(message, userWithCredentials.ed25519Keypair.privateKey)

    const expectedSignature = safeDeposit.fromHex('7d1be99fca80a54ef7a5ad470e5703824cec50257742448b4173f7ad70b708b4b29c3fea8f53555f92a7a3faeb397fdaee53c2cfcdb57abedf6dd1dc2c9b940b')

    expect(signature).toEqual(expectedSignature)

    const valid = safeDeposit.verify(message, signature, userWithCredentials.ed25519Keypair.publicKey)

    expect(valid).toBe(true)

    const tamperedValid = safeDeposit.verify(tamperedMessage, signature, userWithCredentials.ed25519Keypair.publicKey)

    expect(tamperedValid).toBe(false)
})