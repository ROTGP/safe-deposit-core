import { test, expect } from 'vitest'
import sd, { PasswordHashingEffort } from './../../src/safeDeposit'

test('the updating of the credentials of a user', async () => {

    const alicePasshphrase = 'alice password'
    const aliceQRCode = await sd.generateMasterQRCode(alicePasshphrase, PasswordHashingEffort.interactive)
    const alice = await sd.generateUserCredentials(alicePasshphrase, aliceQRCode)

    const newPassphrase = 'abc123'
    const newQRCode = await sd.updateQRCode(alicePasshphrase, aliceQRCode, newPassphrase, PasswordHashingEffort.moderate)
    const updatedAlice = await sd.generateUserCredentials(newPassphrase, newQRCode)

    // same
    expect(alice.uuid).toEqual(updatedAlice.uuid)
    expect(alice.masterKey).toEqual(updatedAlice.masterKey)
    expect(alice.symmetricKey).toEqual(updatedAlice.symmetricKey)

    expect(alice.keyExchangeKeypairSeed).toEqual(updatedAlice.keyExchangeKeypairSeed)
    expect(alice.keyExchangeKeypair.secretKey).toEqual(updatedAlice.keyExchangeKeypair.secretKey)
    expect(alice.keyExchangeKeypair.publicKey).toEqual(updatedAlice.keyExchangeKeypair.publicKey)
    expect(alice.keyExchangeKeypairHash).toEqual(updatedAlice.keyExchangeKeypairHash)

    expect(alice.signingKeypairSeed).toEqual(updatedAlice.signingKeypairSeed)
    expect(alice.signingKeypair.secretKey).toEqual(updatedAlice.signingKeypair.secretKey)
    expect(alice.signingKeypair.publicKey).toEqual(updatedAlice.signingKeypair.publicKey)
    expect(alice.signingKeypairHash).toEqual(updatedAlice.signingKeypairHash)

    // different
    expect(alice.passphrase).not.toEqual(newPassphrase)
    expect(alice.QRCode).not.toEqual(updatedAlice.QRCode)

    expect(alice.apiAuthKeypairSeed).not.toEqual(updatedAlice.apiAuthKeypairSeed)
    expect(alice.apiAuthKeypair.secretKey).not.toEqual(updatedAlice.apiAuthKeypair.secretKey)
    expect(alice.apiAuthKeypair.publicKey).not.toEqual(updatedAlice.apiAuthKeypair.publicKey)
    expect(alice.apiAuthKeypairHash).not.toEqual(updatedAlice.apiAuthKeypairHash)
})
