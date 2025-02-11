import { test, expect, beforeEach } from 'vitest'
import safeDeposit from '../src/safeDeposit'

beforeEach(async () => {
    await safeDeposit.init()
})


test('x', async () => {

    const seed = safeDeposit.randomBytes(64)
})
