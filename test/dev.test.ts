import { test, expect, beforeEach } from 'vitest'
import safeDeposit from '../src/safeDeposit'

import { scrypt, scryptAsync } from '@noble/hashes/scrypt'


beforeEach(async () => {
    await safeDeposit.init()
})


test('x', async () => {

    const seed = safeDeposit.randomBytes(64)
})
