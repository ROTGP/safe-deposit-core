import { test, expect } from 'vitest'
import sd, { PasswordHashingEffort } from '../../src/safeDeposit'

test('master QR code generation with explicit values', async () => {

    const passphrase = 'my long & rambling p@ssword'

    const uuid = sd.randomBytes(16)
    const masterKey = sd.randomBytes(32)
    const auxiliaryKey = sd.randomBytes(16)

    const effort = PasswordHashingEffort.interactive

    const masterQRCode = await sd.generateMasterQRCode(passphrase, effort, uuid, masterKey, auxiliaryKey)

    const extracted = await sd.extractAccountKeyingMaterial(passphrase, masterQRCode)

    expect(masterQRCode).toHaveLength(78)
    expect(uuid).toEqual(extracted.uuid)
    expect(masterKey).toEqual(extracted.masterKey)
    expect(auxiliaryKey).toEqual(extracted.auxiliaryKey)
    expect(effort).toEqual(extracted.effort)
})

test('master QR code generation (blind)', async () => {

    const passphrase = 'RaiñbowT@ble_7!'

    const masterQRCode = await sd.generateMasterQRCode(passphrase, PasswordHashingEffort.interactive)
    const extracted = await sd.extractAccountKeyingMaterial(passphrase, masterQRCode)

    expect(masterQRCode).toHaveLength(78)
    expect(extracted.uuid).toHaveLength(16)
    expect(extracted.masterKey).toHaveLength(32)
    expect(extracted.auxiliaryKey).toHaveLength(16)
})
