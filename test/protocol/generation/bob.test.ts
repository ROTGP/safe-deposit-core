import { test, expect } from 'vitest'
import sd from './../../../src/safeDeposit'
import { bob } from './../../../test/data/users'
import { AccountKeyingMaterial, UserWithCredentials } from './../../../src/types'

test('generate deterministic wrapped master key for bob and then extract it', async () => {

    const wrappedMasterKey = await sd.generateMasterQRCode(bob.passphrase, bob.effort, bob.uuid, bob.masterKey, bob.auxiliaryKey)

    expect(wrappedMasterKey).toEqual(bob.QRCode)

    const accountKeyingMaterial: AccountKeyingMaterial = await sd.extractAccountKeyingMaterial(bob.passphrase, wrappedMasterKey)

    expect(accountKeyingMaterial.uuid).toEqual(bob.uuid)
    expect(accountKeyingMaterial.effort).toEqual(bob.effort)
    expect(accountKeyingMaterial.masterKey).toEqual(bob.masterKey)
    expect(accountKeyingMaterial.auxiliaryKey).toEqual(bob.auxiliaryKey)
})

test('generate user with credentials for bob', async () => {


    const userWithCredentials: UserWithCredentials = await sd.generateUserCredentials(bob.passphrase, bob.QRCode)
    expect(userWithCredentials.symmetricKey).toEqual(bob.symmetricKey)

    const keyExchangeKeypairHash = sd.keypairHash(userWithCredentials.keyExchangeKeypair.secretKey, userWithCredentials.keyExchangeKeypair.publicKey)
    expect(keyExchangeKeypairHash).toEqual(sd.fromHex('228f5a821e5d0ecc46805852ac0e2bae2bcc2bf104bcfeaf94d1aa2acbbb2908e65c3a85c169ef928c5d8c48701f770b56b70d4e28e35323296c2aac7141248d'))

    const signingKeypairHash = sd.keypairHash(userWithCredentials.signingKeypair.secretKey, userWithCredentials.signingKeypair.publicKey)
    expect(signingKeypairHash).toEqual(sd.fromHex('866e68ed9b54ed6bab0f6d51cc22e783f778446e5edcee6fc88af1548cfdbee7e55ae968205b7767c0d223b515e673a920a7e2a96798acfaa6ceff3fc7e9ef2f'))

    const apiAuthKeypairHash = sd.keypairHash(userWithCredentials.apiAuthKeypair.secretKey, userWithCredentials.apiAuthKeypair.publicKey)
    expect(apiAuthKeypairHash).toEqual(sd.fromHex('9d05662a132aa2a5b24b167882a64bb48ce2f3416dd9a1ed7b7264bad8dbe493728eaa04b6ef436a0b7c93246576eec33667e11ead99e054fb9b73365e5b275a'))
})