import { test, expect, beforeEach } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { trent } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

beforeEach(async () => {
    await safeDeposit.init()
})

test('generate deterministic wrapped master key for trent and then extract it', async () => {

    const wrappedMasterKey = safeDeposit.generateMasterQRCode(trent.passphrase, trent.effort, trent.uuid, trent.masterKey)

    expect(wrappedMasterKey).toEqual(trent.QRCode)

    const unwrappedMasterKey = safeDeposit.extractMasterKeyAndApiAuthKeypairFromQRCode(trent.passphrase, wrappedMasterKey).masterKey

    expect(unwrappedMasterKey).toEqual(trent.masterKey)
})

test('generate user with credentials for trent', async () => {

    const userWithCredentials: UserWithCredentials = safeDeposit.generateCredentials(trent.passphrase, trent.QRCode)

    expect(userWithCredentials.symmetricKey).toEqual(trent.symmetricKey)
    expect(userWithCredentials.x25519Keypair.privateKey).toEqual(trent.x25519Keypair.privateKey)
    expect(userWithCredentials.x25519Keypair.publicKey).toEqual(trent.x25519Keypair.publicKey)
    expect(userWithCredentials.ed25519Keypair.privateKey).toEqual(trent.ed25519Keypair.privateKey)
    expect(userWithCredentials.ed25519Keypair.publicKey).toEqual(trent.ed25519Keypair.publicKey)
})