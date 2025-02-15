import { test, expect } from 'vitest'
import sd from './../../../src/safeDeposit'
import { eve } from './../../../test/data/users'
import { AccountKeyingMaterial, UserWithCredentials } from './../../../src/types'

test('generate deterministic wrapped master key for eve and then extract it', async () => {

    const wrappedMasterKey = await sd.generateMasterQRCode(eve.passphrase, eve.effort, eve.uuid, eve.masterKey, eve.auxiliaryKey)

    expect(wrappedMasterKey).toEqual(eve.QRCode)

    const accountKeyingMaterial: AccountKeyingMaterial = await sd.extractAccountKeyingMaterial(eve.passphrase, wrappedMasterKey)

    expect(accountKeyingMaterial.uuid).toEqual(eve.uuid)
    expect(accountKeyingMaterial.effort).toEqual(eve.effort)
    expect(accountKeyingMaterial.masterKey).toEqual(eve.masterKey)
    expect(accountKeyingMaterial.auxiliaryKey).toEqual(eve.auxiliaryKey)
})

test('generate user with credentials for eve', async () => {


    const userWithCredentials: UserWithCredentials = await sd.generateUserCredentials(eve.passphrase, eve.QRCode)
    expect(userWithCredentials.symmetricKey).toEqual(eve.symmetricKey)

    const keyExchangeKeypairHash = sd.keypairHash(userWithCredentials.keyExchangeKeypair.secretKey, userWithCredentials.keyExchangeKeypair.publicKey)
    expect(keyExchangeKeypairHash).toEqual(sd.fromHex('fd85c04a96245f522a972c9d9baca8dec3f7bb428868231153f3dbaab1e380b5da0ecc8a3c47d7f96cc793e69ff711f64922e33ce056d0e6d1f1c92ecda1b704'))

    const signingKeypairHash = sd.keypairHash(userWithCredentials.signingKeypair.secretKey, userWithCredentials.signingKeypair.publicKey)
    expect(signingKeypairHash).toEqual(sd.fromHex('8de2d843fe323968c7a9f806a27886af1b6509a72a7f45dca2acab6f23967999694a27d5573fa0f1aece52661310f55b1a6a57f7d157a9cdc01dfdfdef252e7e'))

    const apiAuthKeypairHash = sd.keypairHash(userWithCredentials.apiAuthKeypair.secretKey, userWithCredentials.apiAuthKeypair.publicKey)
    expect(apiAuthKeypairHash).toEqual(sd.fromHex('74d12e6996a14bc7daabf632c1a0b8a11a08c6fa63af0506821ec75cc002e7f3835165256c4de755a61926b6ad7668bcb7c39d36d7e155ea0a4cf109a105b1b5'))
})