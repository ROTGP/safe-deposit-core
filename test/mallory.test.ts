import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { mallory } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('generate deterministic wrapped master key for mallory and then extract it', async () => {

    await safeDeposit.init()

    const wrappedMasterKey = safeDeposit.generateMasterQRCode(mallory.passphrase, mallory.effort, mallory.uuid, mallory.masterKey)

    expect(wrappedMasterKey).toEqual(mallory.QRCode)

    const unwrappedMasterKey = safeDeposit.extractMasterKeyAndApiAuthKeypairFromQRCode(mallory.passphrase, wrappedMasterKey).masterKey

    expect(unwrappedMasterKey).toEqual(mallory.masterKey)
})

test('generate user with credentials for mallory', async () => {

    await safeDeposit.init()

    const userWithCredentials: UserWithCredentials = safeDeposit.generateCredentials(mallory.passphrase, mallory.QRCode)

    expect(userWithCredentials.symmetricKey).toEqual(mallory.symmetricKey)
    expect(userWithCredentials.x25519Keypair.privateKey).toEqual(mallory.x25519Keypair.privateKey)
    expect(userWithCredentials.x25519Keypair.publicKey).toEqual(mallory.x25519Keypair.publicKey)
    expect(userWithCredentials.ed25519Keypair.privateKey).toEqual(mallory.ed25519Keypair.privateKey)
    expect(userWithCredentials.ed25519Keypair.publicKey).toEqual(mallory.ed25519Keypair.publicKey)
})