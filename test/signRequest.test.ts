import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { bob } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('sign a request', async () => {

    await safeDeposit.init()

    const timestamp = Date.now()

    const nonce = safeDeposit.randomBytes(32)

    const url = 'https://safedepos.it/sign-up/'

    const method = 'POST'

    const payload = {
        some: 'value',
        another: 123,
        andAnother: false
    }

    const requestSignature = safeDeposit.signRequest(
        bob.uuid,
        timestamp,
        nonce,
        url,
        method,
        payload,
        bob.ed25519Keypair.privateKey
    )

    const isValidSignature = safeDeposit.verifyRequestSignature(
        bob.uuid,
        timestamp,
        nonce,
        url,
        method,
        payload,
        bob.ed25519Keypair.publicKey,
        requestSignature
    )

    expect(isValidSignature).toEqual(true)
})
