import { test, expect, beforeEach } from 'vitest'
import sd from '../../src/safeDeposit'

beforeEach(async () => {
    await sd.init()
})

// https://github.com/brycx/Test-Vector-Generation/blob/master/HKDF/hkdf-hmac-sha2-test-vectors.md
test('key derivation (HKDF-Sha512)', async () => {

    let ikm = sd.fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
    let salt = sd.fromHex('000102030405060708090a0b0c')
    let info = sd.fromHex('f0f1f2f3f4f5f6f7f8f9')
    let okm = sd.deriveKeyBasedKey(ikm, 42, info, salt)
    let expectedOkm = sd.fromHex('832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb')
    expect(okm).toEqual(expectedOkm)

    ikm = sd.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f')
    salt = sd.fromHex('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')
    info = sd.fromHex('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    okm = sd.deriveKeyBasedKey(ikm, 82, info, salt)
    expectedOkm = sd.fromHex('ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93')
    expect(okm).toEqual(expectedOkm)

    ikm = sd.fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
    salt = sd.fromHex('')
    info = sd.fromHex('')
    okm = sd.deriveKeyBasedKey(ikm, 42, info, salt)
    expectedOkm = sd.fromHex('f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac')
    expect(okm).toEqual(expectedOkm)

    ikm = sd.fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
    salt = sd.fromString('s$#$#%$#SBGHWE@#W#lt')
    info = sd.fromString('random InF\0')
    okm = sd.deriveKeyBasedKey(ikm, 256, info, salt)
    expectedOkm = sd.fromHex('e93182a8af74a1e70a6202075759bbbceb1926a18aa9f9ee317965570b507cea7ef11f94d83760bb6f8a2f6031edb581c1ae43f45ead820223d34c6ffadab43d3cfaf9cd782b8aa7bd2ebab8663b51d4e40b9a659a7e262630581fee55ac986770e88f580c8d8b82deba4d1c28bce4dc7a579456ed30a94a1782cab84699a4302ef8d24f23e9122ef2daaba4fd3d84c812c4b3a8d4788397fd38ddccf59d60a8330000cb04e5aa2d3e16e56dbccd8ca68020abcb3bc097788d38dfd2e241ba7772ba188c29d7f4d010b421875c9e7165ed2ebcf338b81071eca62300c9ca9840b6f1fc9403752536b3eca147e9fbf127ff88d33b984582ced74fa029b50f441e')
    expect(okm).toEqual(expectedOkm)

    ikm = sd.fromString('pass\0word')
    salt = sd.fromString('saltSALTSALTSALTSALTSALTSALTSALTSALTSALTSALTSALTSALT')
    info = sd.fromHex('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    okm = sd.deriveKeyBasedKey(ikm, 16, info, salt)
    expectedOkm = sd.fromHex('8ae15623215eaaa156bad552f411c4ad')
    expect(okm).toEqual(expectedOkm)
})