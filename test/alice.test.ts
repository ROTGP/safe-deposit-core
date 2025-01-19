import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { alice } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('generate deterministic wrapped master key for alice and then extract it', async () => {

    await safeDeposit.init()

    const wrappedMasterKey = safeDeposit.generateMasterQRCode(alice.passphrase, alice.effort, alice.uuid, alice.masterKey)

    expect(wrappedMasterKey).toEqual(alice.QRCode)

    const unwrappedMasterKey = safeDeposit.extractMasterKeyAndApiAuthKeypairFromQRCode(alice.passphrase, wrappedMasterKey).masterKey

    expect(unwrappedMasterKey).toEqual(alice.masterKey)
})

test('generate user with credentials for alice', async () => {

    await safeDeposit.init()

    const userWithCredentials: UserWithCredentials = safeDeposit.generateCredentials(alice.passphrase, alice.QRCode)

    expect(userWithCredentials.symmetricKey).toEqual(alice.symmetricKey)
    expect(userWithCredentials.x25519Keypair.privateKey).toEqual(alice.x25519Keypair.privateKey)
    expect(userWithCredentials.x25519Keypair.publicKey).toEqual(alice.x25519Keypair.publicKey)
    expect(userWithCredentials.ed25519Keypair.privateKey).toEqual(alice.ed25519Keypair.privateKey)
    expect(userWithCredentials.ed25519Keypair.publicKey).toEqual(alice.ed25519Keypair.publicKey)
})