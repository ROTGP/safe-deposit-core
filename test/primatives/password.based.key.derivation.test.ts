import { test, expect, beforeEach } from 'vitest'
import sd, { PasswordHashingEffort } from '../../src/safeDeposit'
import { argon2id } from '@noble/hashes/argon2'

beforeEach(async () => {
    await sd.init()
})

// test vectors *without* the secret 'pepper' param, so we test
// LibSodium output against Noble
test('password based key derivation (Argon2ID)', async () => {

    const password = 'my$uperSecre+P@$$w0rd'
    const salt = sd.fromHex('01020304050607080102030405060708')
    const resultLibSodium = sd.generatePasswordHash(40, password, salt, PasswordHashingEffort.interactive)
    const resultNoble = argon2id(password, salt, { dkLen: 40, t: 2, m: (2 ** 26) / 1024, p: 1 })

    expect(resultLibSodium).toEqual(resultNoble)
})