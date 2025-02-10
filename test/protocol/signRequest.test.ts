import { test, expect } from 'vitest'
import safeDeposit from './../../src/safeDeposit'
import { bob } from './../../test/data/users'

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
        bob.signingKeypair.secretKey
    )

    const isValidSignature = safeDeposit.verifyRequestSignature(
        bob.uuid,
        timestamp,
        nonce,
        url,
        method,
        payload,
        bob.signingKeypair.publicKey,
        requestSignature
    )

    expect(isValidSignature).toEqual(true)
})
