import { test, expect } from 'vitest'
import safeDeposit from '../src/safeDeposit'
import { alice, bob, eve, mallory, trent } from '../test/data/users'
import { UserWithCredentials } from '../src/types'

test('generate deterministic wrapped master key for eve and then extract it', async () => {

    await safeDeposit.init()

    const person = trent

    const x = safeDeposit.generateUser(person.passphrase, person.effort, person.uuid, person.masterKey)

    console.log(safeDeposit.toHex(x.QRCode))

    // safeDeposit.prettyUser(safeDeposit.generateUser(person.passphrase, person.effort, person.uuid, person.masterKey))
})
