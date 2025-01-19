import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { bob } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('generate deterministic wrapped master key for bob and then extract it', async () => {

    await safeDeposit.init()

    const wrappedMasterKey = safeDeposit.generateMasterQRCode(bob.passphrase, bob.effort, bob.uuid, bob.masterKey)

    expect(wrappedMasterKey).toEqual(bob.QRCode)

    const unwrappedMasterKey = safeDeposit.extractMasterKeyAndApiAuthKeypairFromQRCode(bob.passphrase, wrappedMasterKey).masterKey

    expect(unwrappedMasterKey).toEqual(bob.masterKey)
})

test('generate user with credentials for bob', async () => {

    await safeDeposit.init()

    const userWithCredentials: UserWithCredentials = safeDeposit.generateCredentials(bob.passphrase, bob.QRCode)

    expect(userWithCredentials.symmetricKey).toEqual(bob.symmetricKey)
    expect(userWithCredentials.x25519Keypair.privateKey).toEqual(bob.x25519Keypair.privateKey)
    expect(userWithCredentials.x25519Keypair.publicKey).toEqual(bob.x25519Keypair.publicKey)
    expect(userWithCredentials.ed25519Keypair.privateKey).toEqual(bob.ed25519Keypair.privateKey)
    expect(userWithCredentials.ed25519Keypair.publicKey).toEqual(bob.ed25519Keypair.publicKey)
})