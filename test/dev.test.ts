import { test } from 'vitest'
import safeDeposit, { PasswordHashingEffort } from '../src/safeDeposit'

test('x', async () => {

    const salt = safeDeposit.randomBytes(16)
})
