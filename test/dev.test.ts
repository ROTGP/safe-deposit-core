import { test, expect } from 'vitest'
import safeDeposit, { PasswordHashingEffort } from '../src/safeDeposit'

test('x', async () => {

    const seed = safeDeposit.randomBytes(64)

    // for (var i = 0; i < 1000; i++) {
    //     console.log(safeDeposit.randomAlphaNumeric(5))
    // }

    // console.log('crypto_pwhash_OPSLIMIT_INTERACTIVE:', safeDeposit.sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE)
    // console.log('crypto_pwhash_OPSLIMIT_MODERATE:', safeDeposit.sodium.crypto_pwhash_OPSLIMIT_MODERATE)
    // console.log('crypto_pwhash_OPSLIMIT_SENSITIVE:', safeDeposit.sodium.crypto_pwhash_OPSLIMIT_SENSITIVE)

    // console.log('crypto_pwhash_MEMLIMIT_INTERACTIVE:', safeDeposit.sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
    // console.log('crypto_pwhash_MEMLIMIT_MODERATE:', safeDeposit.sodium.crypto_pwhash_MEMLIMIT_MODERATE)
    // console.log('crypto_pwhash_MEMLIMIT_SENSITIVE:', safeDeposit.sodium.crypto_pwhash_MEMLIMIT_SENSITIVE)

    const memLimits = {
        [PasswordHashingEffort.interactive]: 67108864,
        [PasswordHashingEffort.moderate]: 268435456,
        [PasswordHashingEffort.sensitive]: 1073741824,
    }

    console.log(2 ** 26, 67108864, 2 ** 28, 268435456, 2 ** 30, 1073741824)


    // console.log(opsLimits[PasswordHashingEffort.interactive])
})
