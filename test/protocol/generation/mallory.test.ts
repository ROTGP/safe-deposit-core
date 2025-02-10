import { test, expect, beforeEach } from 'vitest'
import sd from './../../../src/safeDeposit'
import { mallory } from './../../../test/data/users'
import { AccountKeyingMaterial, UserWithCredentials } from './../../../src/types'

beforeEach(async () => {
    await sd.init()
})

test('generate deterministic wrapped master key for mallory and then extract it', async () => {

    const wrappedMasterKey = sd.generateMasterQRCode(mallory.passphrase, mallory.effort, mallory.uuid, mallory.masterKey, mallory.auxiliaryKey)

    expect(wrappedMasterKey).toEqual(mallory.QRCode)

    const accountKeyingMaterial: AccountKeyingMaterial = sd.extractAccountKeyingMaterial(mallory.passphrase, wrappedMasterKey)

    expect(accountKeyingMaterial.uuid).toEqual(mallory.uuid)
    expect(accountKeyingMaterial.effort).toEqual(mallory.effort)
    expect(accountKeyingMaterial.masterKey).toEqual(mallory.masterKey)
    expect(accountKeyingMaterial.auxiliaryKey).toEqual(mallory.auxiliaryKey)
})

test('generate user with credentials for mallory', async () => {


    const userWithCredentials: UserWithCredentials = sd.generateUserCredentials(mallory.passphrase, mallory.QRCode)
    expect(userWithCredentials.symmetricKey).toEqual(mallory.symmetricKey)

    const keyExchangeKeypairHash = sd.keypairHash(userWithCredentials.keyExchangeKeypair.secretKey, userWithCredentials.keyExchangeKeypair.publicKey)
    expect(keyExchangeKeypairHash).toEqual(sd.fromHex('c93a278b2bf0cde396d43a3ce88e3f8ae69b6106c26966f94ae5cb327329c4a32bdbe0a26dc7c6f152285c017cd29786e6879f954d24cfcbcab2e2d837496b53'))

    const signingKeypairHash = sd.keypairHash(userWithCredentials.signingKeypair.secretKey, userWithCredentials.signingKeypair.publicKey)
    expect(signingKeypairHash).toEqual(sd.fromHex('80dee8fa6d0e72c8185a1df75a81bfaefe57c35b8ec9eae271697a094f05bf5209a3425fb10134e27c13c49c606f2608bc618f05f9d9de92e3444059d705ddfc'))

    const apiAuthKeypairHash = sd.keypairHash(userWithCredentials.apiAuthKeypair.secretKey, userWithCredentials.apiAuthKeypair.publicKey)
    expect(apiAuthKeypairHash).toEqual(sd.fromHex('f9f1f660c7f7d8adcabd3f70ec9cc6348009d52edc9bb7c82449729a9e437fdc6fb31e6d487d6944475b01c7933d94ea60e3c551a4f478071b5c57241ba17250'))
})