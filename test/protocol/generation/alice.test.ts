import { test, expect, beforeEach } from 'vitest'
import sd from './../../../src/safeDeposit'
import { alice } from './../../../test/data/users'
import { AccountKeyingMaterial, UserWithCredentials } from './../../../src/types'

beforeEach(async () => {
    await sd.init()
})

test('generate deterministic wrapped master key for alice and then extract it', async () => {

    const wrappedMasterKey = sd.generateMasterQRCode(alice.passphrase, alice.effort, alice.uuid, alice.masterKey, alice.auxiliaryKey)

    expect(wrappedMasterKey).toEqual(alice.QRCode)

    const accountKeyingMaterial: AccountKeyingMaterial = sd.extractAccountKeyingMaterial(alice.passphrase, wrappedMasterKey)

    expect(accountKeyingMaterial.uuid).toEqual(alice.uuid)
    expect(accountKeyingMaterial.effort).toEqual(alice.effort)
    expect(accountKeyingMaterial.masterKey).toEqual(alice.masterKey)
    expect(accountKeyingMaterial.auxiliaryKey).toEqual(alice.auxiliaryKey)
})

test('generate user with credentials for alice', async () => {


    const userWithCredentials: UserWithCredentials = sd.generateUserCredentials(alice.passphrase, alice.QRCode)
    expect(userWithCredentials.symmetricKey).toEqual(alice.symmetricKey)

    const keyExchangeKeypairHash = sd.keypairHash(userWithCredentials.keyExchangeKeypair.secretKey, userWithCredentials.keyExchangeKeypair.publicKey)
    expect(keyExchangeKeypairHash).toEqual(sd.fromHex('7daa11188976283bfef38bea8412b37ac5cb64bfd14fa52b1f7aa07a3bcd7ad566e64c65f9e2d388c3d03504d36c7fba15dbb4ae89e6279cab8025df7e46deab'))

    const signingKeypairHash = sd.keypairHash(userWithCredentials.signingKeypair.secretKey, userWithCredentials.signingKeypair.publicKey)
    expect(signingKeypairHash).toEqual(sd.fromHex('2f2873f42ec791fc682a57e991626a598084d0421854eb0945ff0f4739bad9299520d325cdc78e117222dc3ed58c846cc7f3b2e2c4ca5f177648fff125ded9d9'))

    const apiAuthKeypairHash = sd.keypairHash(userWithCredentials.apiAuthKeypair.secretKey, userWithCredentials.apiAuthKeypair.publicKey)
    expect(apiAuthKeypairHash).toEqual(sd.fromHex('68a35aa1881871ba6fd42aa66036c836f25b70695e9bdd534668c886e58c441c55962702c9507c9daabca71c29cf7b6410050912e77a7ad73128513b04c498dd'))
})