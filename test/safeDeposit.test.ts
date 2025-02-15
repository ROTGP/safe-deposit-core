import { test, expect } from 'vitest'
import sd, { KeyType } from './../src/safeDeposit'

test('random byte generation', async () => {

    const bytes1 = sd.randomBytes(10)
    const bytes2 = sd.randomBytes(10)

    expect(bytes1).to.equal(bytes1)
    expect(bytes1.length).toBe(10)
    expect(bytes1).not.to.equal(bytes2)
})

test('context from key type', async () => {

    expect(sd.contextFromKeyType(KeyType.apiAuthentication)).toBe('apiAuthe')
    expect(sd.contextFromKeyType(KeyType.keyExchange)).toBe('keyExcha')
    expect(sd.contextFromKeyType(KeyType.master)).toBe('master__')
    expect(sd.contextFromKeyType(KeyType.signing)).toBe('signing_')
    expect(sd.contextFromKeyType(KeyType.symmetric)).toBe('symmetri')
})
