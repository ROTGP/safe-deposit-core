import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { bob } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('generate deterministic wrapped master key for bob and then extract it', async () => {

    await safeDeposit.init()

    const wrappedMasterKey = safeDeposit.generateMasterQRCode(bob.alias, bob.passphrase, bob.pin, bob.effort, bob.masterKey)

    expect(wrappedMasterKey).toEqual(bob.QRCode)

    const unwrappedMasterKey = safeDeposit.extractMasterKeyFromQRCode(bob.alias, bob.passphrase, bob.pin, wrappedMasterKey)

    expect(unwrappedMasterKey).toEqual(bob.masterKey)
})

test('generate user with credentials for bob', async () => {

    await safeDeposit.init()

    const userWithCredentials: UserWithCredentials = safeDeposit.generateCredentials(bob.alias, bob.passphrase, bob.pin, bob.QRCode)

    expect(userWithCredentials.symmetricKey).toEqual(bob.symmetricKey)
    expect(userWithCredentials.x25519Keypair.privateKey).toEqual(bob.x25519Keypair.privateKey)
    expect(userWithCredentials.x25519Keypair.publicKey).toEqual(bob.x25519Keypair.publicKey)
    expect(userWithCredentials.ed25519Keypair.privateKey).toEqual(bob.ed25519Keypair.privateKey)
    expect(userWithCredentials.ed25519Keypair.publicKey).toEqual(bob.ed25519Keypair.publicKey)
})