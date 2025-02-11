import { test, expect, beforeEach } from 'vitest'
import safeDeposit from '../src/safeDeposit'

import { scrypt, scryptAsync } from '@noble/hashes/scrypt'
import { alice } from './data/users'


beforeEach(async () => {
    await safeDeposit.init()
})


test('x', async () => {

    const seed = safeDeposit.randomBytes(64)
})
