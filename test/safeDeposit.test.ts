import { test, expect } from 'vitest'
import safeDeposit, { KeyType } from '../src/safeDeposit'

test('random byte generation', async () => {

    await safeDeposit.init()

    const bytes1 = safeDeposit.randomBytes(10)
    const bytes2 = safeDeposit.randomBytes(10)

    expect(bytes1).to.equal(bytes1)
    expect(bytes1.length).toBe(10)
    expect(bytes1).not.to.equal(bytes2)
})

test('context from key type', async () => {

    await safeDeposit.init()

    expect(safeDeposit.contextFromKeyType(KeyType.ed25519)).toBe('ed25519_')
    expect(safeDeposit.contextFromKeyType(KeyType.master)).toBe('master__')
    expect(safeDeposit.contextFromKeyType(KeyType.symmetric)).toBe('symmetri')
    expect(safeDeposit.contextFromKeyType(KeyType.wrapAuthentication)).toBe('wrapAuth')
    expect(safeDeposit.contextFromKeyType(KeyType.wrapEncryption)).toBe('wrapEncr')
    expect(safeDeposit.contextFromKeyType(KeyType.x25519)).toBe('x25519__')
})
