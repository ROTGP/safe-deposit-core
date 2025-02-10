import { test, expect, beforeEach } from 'vitest'
import sd from '../../src/safeDeposit'

beforeEach(async () => {
    await sd.init
})

test('int to bytes and bytes to int', async () => {

    expect(sd.intToBytes(0)).toEqual(Uint8Array.from([0, 0]))
    expect(sd.intToBytes(1)).toEqual(Uint8Array.from([1, 0]))
    expect(sd.intToBytes(1000)).toEqual(Uint8Array.from([232, 3]))
    expect(sd.intToBytes(2025)).toEqual(Uint8Array.from([233, 7]))
    expect(sd.intToBytes(65535)).toEqual(Uint8Array.from([255, 255]))

    expect(sd.bytesToInt(sd.intToBytes(0))).toEqual(0)
    expect(sd.bytesToInt(sd.intToBytes(1))).toEqual(1)
    expect(sd.bytesToInt(sd.intToBytes(1000))).toEqual(1000)
    expect(sd.bytesToInt(sd.intToBytes(2025))).toEqual(2025)
    expect(sd.bytesToInt(sd.intToBytes(65535))).toEqual(65535)
})
