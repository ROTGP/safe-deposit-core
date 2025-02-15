import { test, expect } from 'vitest'
import sd from '../../src/safeDeposit'

// https://datatracker.ietf.org/doc/html/rfc3394#page-30
test('key-wrap (AES-KW)', async () => {

    const kek = sd.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    const keyToWrap = sd.fromHex('00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f')
    const wrappedKey = sd.wrapKey(kek, keyToWrap)
    const wrappedKeyExpected = sd.fromHex('28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21')

    expect(kek).toHaveLength(32)
    expect(keyToWrap).toHaveLength(32)
    expect(wrappedKey).toHaveLength(40)

    expect(wrappedKey).toEqual(wrappedKeyExpected)
    const unwrappedKey = sd.unwrapKey(kek, wrappedKey)
    expect(unwrappedKey).toEqual(keyToWrap)
    expect(unwrappedKey).toHaveLength(32)
})