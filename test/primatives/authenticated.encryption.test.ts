import { test, expect, beforeEach } from 'vitest'
import sd from '../../src/safeDeposit'

beforeEach(async () => {
    await sd.init()
})


// https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03#page-9
test('authenticated encryption and decryption (xchacha20-poly1305)', async () => {

    const value = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    const key = sd.fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
    const nonce = sd.fromHex('404142434445464748494a4b4c4d4e4f5051525354555657')
    const aad = sd.fromHex('50515253c0c1c2c3c4c5c6c7')

    const cipherText = sd.symmetricEncrypt(sd.fromString(value), key, nonce, aad)

    const expectedCipherText = sd.fromHex('bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e')
    const expectedTag = sd.fromHex('c0875924c1c7987947deafd8780acf49')

    // nonce length + algo + 2 bytes for aad length + the aad itself
    const expectedMeta = Uint8Array.from([...nonce, ...sd.intToBytes(aad.length), ...aad])

    const tagLength = 16

    expect(sd.subArray(cipherText, expectedMeta.length, cipherText.length - expectedMeta.length - tagLength)).toEqual(expectedCipherText)
    expect(sd.subArray(cipherText, cipherText.length - tagLength)).toEqual(expectedTag)
    expect(sd.subArray(cipherText, 0, expectedMeta.length)).toEqual(expectedMeta)

    const clearText = sd.symmetricDecrypt(cipherText, key)

    expect(sd.toString(clearText)).toEqual(value)
})
