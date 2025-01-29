import { test, expect, beforeEach } from 'vitest'
import safeDeposit, { PasswordHashingEffort } from '../src/safeDeposit'
import { alice, bob, eve, mallory, trent } from '../test/data/users'

beforeEach(async () => {
    await safeDeposit.init()
})

test('the updating of the credentials of a user', async () => {

    const person = alice

    const newPassphrase = 'abc123'

    const newEffort = PasswordHashingEffort.interactive

    const newQRCode = safeDeposit.updateQRCode(person.passphrase, person.QRCode, newPassphrase, newEffort)

    const userWithUpdatedCredentialsAndMasterKey = safeDeposit.generateCredentialsWithMasterKey(newPassphrase, newQRCode)

    // safeDeposit.prettyUser(userWithUpdatedCredentialsAndMasterKey)

    // same
    expect(person.uuid).toEqual(userWithUpdatedCredentialsAndMasterKey.uuid)
    expect(person.masterKey).toEqual(userWithUpdatedCredentialsAndMasterKey.masterKey)
    expect(person.symmetricKey).toEqual(userWithUpdatedCredentialsAndMasterKey.symmetricKey)
    expect(person.ed25519Keypair.privateKey).toEqual(userWithUpdatedCredentialsAndMasterKey.ed25519Keypair.privateKey)
    expect(person.ed25519Keypair.publicKey).toEqual(userWithUpdatedCredentialsAndMasterKey.ed25519Keypair.publicKey)
    expect(person.x25519Keypair.privateKey).toEqual(userWithUpdatedCredentialsAndMasterKey.x25519Keypair.privateKey)
    expect(person.x25519Keypair.publicKey).toEqual(userWithUpdatedCredentialsAndMasterKey.x25519Keypair.publicKey)

    // different
    expect(person.passphrase).not.toEqual(newPassphrase)
    expect(person.QRCode).not.toEqual(userWithUpdatedCredentialsAndMasterKey.QRCode)
    expect(person.apiAuthKeypair.privateKey).not.toEqual(userWithUpdatedCredentialsAndMasterKey.apiAuthKeypair.privateKey)
    expect(person.apiAuthKeypair.publicKey).not.toEqual(userWithUpdatedCredentialsAndMasterKey.apiAuthKeypair.publicKey)
})
