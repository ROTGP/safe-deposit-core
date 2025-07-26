import { test, expect } from 'vitest'
import sd from './../../../src/safeDeposit'
import { trent } from './../../../test/data/users'
import { AccountKeyingMaterial, UserWithCredentials } from './../../../src/types'

test('generate deterministic wrapped master key for trent and then extract it', async () => {

    const wrappedMasterKey = await sd.generateMasterQRCode(trent.passphrase, trent.effort, trent.uuid, trent.masterKey, trent.auxiliaryKey)

    expect(wrappedMasterKey).toEqual(trent.masterQRCode)

    const accountKeyingMaterial: AccountKeyingMaterial = await sd.extractAccountKeyingMaterial(trent.passphrase, wrappedMasterKey)

    expect(accountKeyingMaterial.uuid).toEqual(trent.uuid)
    expect(accountKeyingMaterial.effort).toEqual(trent.effort)
    expect(accountKeyingMaterial.masterKey).toEqual(trent.masterKey)
    expect(accountKeyingMaterial.auxiliaryKey).toEqual(trent.auxiliaryKey)
})

test('generate user with credentials for trent', async () => {

    const userWithCredentials: UserWithCredentials = await sd.generateUserCredentials(trent.passphrase, trent.masterQRCode)
    expect(userWithCredentials.symmetricKey).toEqual(trent.symmetricKey)

    const keyExchangeKeypairHash = sd.keypairHash(userWithCredentials.keyExchangeKeypair.secretKey, userWithCredentials.keyExchangeKeypair.publicKey)
    expect(keyExchangeKeypairHash).toEqual(sd.fromHex('0f725136a7bda2e58ddfbd2273068dfeb892176314e19187666b45c9ad5b7e36ee25493dbc7d467fe685d17b8b684183e5ee62d069e6c67e78f68a77c95a6855'))

    const signingKeypairHash = sd.keypairHash(userWithCredentials.signingKeypair.secretKey, userWithCredentials.signingKeypair.publicKey)
    expect(signingKeypairHash).toEqual(sd.fromHex('0de993c2cfe4ff68f4e6586b7f6ca5783948cd83c58efdcffeb8ccb6bbdd224a1e15584c421c234d86ccb5d955daa1e6d7cab9c4e221ede3cf7635b39b4f38db'))

    const apiAuthKeypairHash = sd.keypairHash(userWithCredentials.apiAuthKeypair.secretKey, userWithCredentials.apiAuthKeypair.publicKey)
    expect(apiAuthKeypairHash).toEqual(sd.fromHex('d1eb0777626d04a02d85a28871cf73f3a6288ad81d1dc904f460e549d7850faa5da3f3c66ebaa45d53909e0240818e60cdb0a7120ebc548adc4054e1bf04d470'))

    expect(userWithCredentials.identity).toEqual(trent.identity)
})