import { PasswordHashingEffort } from '../../src/safeDeposit'
import { TestUser } from './../../src/types'

const fromHexString = (hexString) => Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

export const alice: TestUser = {

    alias: 'aly'

    ,

    passphrase: 'cooCoo!12'

    ,

    pin: '242424'

    ,

    QRCode: fromHexString('000049760b7d51917137cb0c0cc8015da1020bdeacb964f265a504aaf4e7dc480f4a97b6087977a9d35a71f48403913d44abe2d16a08f010e983af6252bbf3c3eb3366b49f09')

    ,

    masterKey: fromHexString('a03c194cd50e1e89e81b88832b2ed57d66afd081d4c1038d75611ea8598a9552')

    ,

    effort: PasswordHashingEffort.interactive

    ,

    symmetricKey: fromHexString('256e226915a516c08670e62f944b5de42b2c68d00b57101da92066442386e6ea')

    ,

    x25519Keypair: {

        privateKey: fromHexString('60c77d3f6577228d7cf7bb52d8a3f45d0b07abe1c421445a80e482d2f36b40c0'),

        publicKey: fromHexString('fa55fd948ca48fe9401213d524deab7602048053948de7d6ab289de59864bd63')
    }

    ,

    ed25519Keypair: {

        privateKey: fromHexString('1688d12e8e190b1e109e39de2f180ad70f569860986dd6d3a7ce3c6cafba285202cf90b7067172aa92ecb7f5e096ab7b2b8315a521ec93d54cf7bef8843613c0'),

        publicKey: fromHexString('02cf90b7067172aa92ecb7f5e096ab7b2b8315a521ec93d54cf7bef8843613c0')
    }
}

export const bob: TestUser = {

    alias: 'bobbyBoy12'

    ,

    passphrase: 'too many secret$'

    ,

    pin: '809040'

    ,

    QRCode: fromHexString('00019cf84cb0e021954558c61ca4a5487e91cf432c1934683c53194e544bb88c8964b7b366346477e5ab755aa708191023cb121abb834529f29d21b805fe66b21b7f9d109587')

    ,

    masterKey: fromHexString('d1ce910619ece0a42d9ce53d80f79274229a63dc3d8e4748eef7977e482931c7')

    ,

    effort: PasswordHashingEffort.moderate

    ,

    symmetricKey: fromHexString('ec5fdc5eb99d4f2bab7cd4c1b44c7840252938625255c13f474eb21768d348f7')

    ,

    x25519Keypair: {

        privateKey: fromHexString('00da2368c594e7f4635e099195fc434a85bd3826c9b60acea7bdb93b60b53c05'),

        publicKey: fromHexString('f0fcf7c636b22270b43aa10382210e1bb797970ff641c66c9b2b21bd2574ee4c')
    }

    ,

    ed25519Keypair: {

        privateKey: fromHexString('3223afc7982ab69768835871fbce251a1a6a1ecb74a307e67f27b52b9e1a17d1c3ddb185792d15940cce287b693018d14f7b73286a4d8d780751121d417636cc'),

        publicKey: fromHexString('c3ddb185792d15940cce287b693018d14f7b73286a4d8d780751121d417636cc')
    }
}
