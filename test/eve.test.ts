import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { eve } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('generate deterministic wrapped master key for eve and then extract it', async () => {

    await safeDeposit.init()

    const wrappedMasterKey = safeDeposit.generateMasterQRCode(eve.passphrase, eve.effort, eve.uuid, eve.masterKey)

    expect(wrappedMasterKey).toEqual(eve.QRCode)

    const unwrappedMasterKey = safeDeposit.extractMasterKeyFromQRCode(eve.passphrase, wrappedMasterKey)

    expect(unwrappedMasterKey).toEqual(eve.masterKey)
})

test('generate user with credentials for eve', async () => {

    await safeDeposit.init()

    const userWithCredentials: UserWithCredentials = safeDeposit.generateCredentials(eve.passphrase, eve.QRCode)

    expect(userWithCredentials.symmetricKey).toEqual(eve.symmetricKey)
    expect(userWithCredentials.x25519Keypair.privateKey).toEqual(eve.x25519Keypair.privateKey)
    expect(userWithCredentials.x25519Keypair.publicKey).toEqual(eve.x25519Keypair.publicKey)
    expect(userWithCredentials.ed25519Keypair.privateKey).toEqual(eve.ed25519Keypair.privateKey)
    expect(userWithCredentials.ed25519Keypair.publicKey).toEqual(eve.ed25519Keypair.publicKey)
})