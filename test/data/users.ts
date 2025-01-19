import { PasswordHashingEffort } from '../../src/safeDeposit'
import { TestUser } from './../../src/types'

const fromHexString = (hexString: string) => Uint8Array.from(hexString.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));

// Person A
export const alice: TestUser = {

    uuid: fromHexString('67076e5ccd')

    ,

    passphrase: "O say can you see by the dawn’s early light"

    ,

    QRCode: fromHexString('67076e5ccd0000919ff46050c5dea353488fa09bc511e7b6807bd554aa10f18838f3e2718cf9b099aca9b2c9bd0a344dffbeef30853d0daba1d0d3d00118b4dac7cb0bc87def532182')

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

    ,

    apiAuthKeypair: {

        privateKey: fromHexString('06c0bf91e510ecad848d7036316fe2aaeb31ff507b5fa2dfc164b904cb075b73b2c77f80bd9ec200e4c10d399d3642e5e9f6eb583c7c9ec2abc4ada1bc4d681b'),

        publicKey: fromHexString('b2c77f80bd9ec200e4c10d399d3642e5e9f6eb583c7c9ec2abc4ada1bc4d681b')
    }
}

// Person B
export const bob: TestUser = {

    uuid: fromHexString('b7de4b4268')

    ,

    passphrase: 'too many secret$'

    ,

    QRCode: fromHexString('b7de4b42680001d7766d877ea6aa83f091a0774a45f70cd079cc554128cd61f07369c9ba02833cd66f0bcf3d3b1b2e4fa420924d2a1c0680afd7443fa5d4e6f6e479b1e4143e5880ca')

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

    ,

    apiAuthKeypair: {

        privateKey: fromHexString('8fd9fdf7016c5d7ba84cff2df76902ebb27293e182256ff1416c9dba56ad88ee2ce94991604a71f6ce94c8605ea4d5a7df854f8e855a5ac4e37e92d3a74b5f5f'),

        publicKey: fromHexString('2ce94991604a71f6ce94c8605ea4d5a7df854f8e855a5ac4e37e92d3a74b5f5f')
    }
}

// Eavesdropping Eve
export const eve: TestUser = {

    uuid: fromHexString('31cbbb3aad')

    ,

    passphrase: 'bigBlueShark-44'

    ,

    QRCode: fromHexString('31cbbb3aad0000a6cbb01b3dc5dff1cc93e17a54059703ff37e5f5afde65ede12bc0dd77010d6e4ffdf66e639ad45b0d633a2564ddb1461ef859c6ce8dfc5ed907c73718c26590f812')

    ,

    masterKey: fromHexString('ab3b595128ff74cc4ac5080b0a3526707adb9629db326921613b406a7946d08a')

    ,

    effort: PasswordHashingEffort.interactive

    ,

    symmetricKey: fromHexString('a5e5c81fde7e1d7b5199ee20c432ec940044e3b632c43305461fa9203713d5da')

    ,

    x25519Keypair: {

        privateKey: fromHexString('fd0137de08fd401fe4ae4f6105091745854f5067ef56d568d1a835cd22a96131'),

        publicKey: fromHexString('2c3ad1ac954096607ca19df1e179d8a03305ed558d720ddcc6f6f0f3965d8804')
    }

    ,

    ed25519Keypair: {

        privateKey: fromHexString('91115eef53316b91d185284201e301258fd1dc20c9a96bf26f148588076e9d8355662fa12119ee4ff73328dd3e24afd15b41427442e73db3812aea3290ee77e0'),

        publicKey: fromHexString('55662fa12119ee4ff73328dd3e24afd15b41427442e73db3812aea3290ee77e0')
    }

    ,

    apiAuthKeypair: {

        privateKey: fromHexString('f163a8ef7eb18f02c2528a80eeeec2f672ff6fb26d1fd3a13edf87e2c4e9c81021b92038b8a64cc18bb47fe2892c6f170954d244165df39c3745f7400d572c66'),

        publicKey: fromHexString('21b92038b8a64cc18bb47fe2892c6f170954d244165df39c3745f7400d572c66')
    }
}

// Malicious Mallory
export const mallory: TestUser = {

    uuid: fromHexString('3c7ea989af')

    ,

    passphrase: 'qwertyuiop'

    ,

    QRCode: fromHexString('3c7ea989af00010fe1670e9cd6bd2063704f34827d59e4d6f4e3bef6baad868e2be4e5c7e4a3705422fb1d1d141a8beefef2c3f378c04cdf242c3b1d9cf55ae2c92115e20e43d7a5b2')

    ,

    masterKey: fromHexString('2c1a59ca4ae4262ecaf6adf344a02955697f90c0a2825626a62079cc95d954af')

    ,

    effort: PasswordHashingEffort.moderate

    ,

    symmetricKey: fromHexString('0c856c5ed8986e2cf49f7c7154256e5a2eb0626236df2d286c9c706cee4f1685')

    ,

    x25519Keypair: {

        privateKey: fromHexString('6f89aa6cfe195ec58c523c042e8d812b411136ae51cfc4d42ce7c531b3029f56'),

        publicKey: fromHexString('590827f5ec5da6798c0678cea44cd48a4df416122b66a7ca10c60ddeadb24a35')
    }

    ,

    ed25519Keypair: {

        privateKey: fromHexString('5b8376114189694160232b64e418857369dd08f5a39684b173eaad606d55591f3c35f2b251c4b2236cebe0b438b9c0c32b7bb259f693c88772c3ba69d07de274'),

        publicKey: fromHexString('3c35f2b251c4b2236cebe0b438b9c0c32b7bb259f693c88772c3ba69d07de274')
    }

    ,

    apiAuthKeypair: {

        privateKey: fromHexString('3c56dadf691aad44168a576b9bc33a60eaf5e6421b690e254c591cf36483dd8a1a793ca301d8e08e5c941b613ece44666111eba0dc7acf1ee801f2eb06c5d5ce'),

        publicKey: fromHexString('1a793ca301d8e08e5c941b613ece44666111eba0dc7acf1ee801f2eb06c5d5ce')
    }
}

// Trustworthy Trent
export const trent: TestUser = {

    uuid: fromHexString('11f0d3b72f')

    ,

    passphrase: 'RaiñbowT@ble_7!'

    ,

    QRCode: fromHexString('11f0d3b72f0000d86228ec217e12f075449e284b0965e90d8d7df16e43efba70528586d4853a77eaca1afebe1ff69f7f024cb889fb3fbadca4dd1d42345465063686ef49ea30288744')

    ,

    masterKey: fromHexString('ad0fa2e242d6a4f73657d77e7f04a2a3076e00eb7bb232579cdbaee3308781e6')

    ,

    effort: PasswordHashingEffort.interactive

    ,

    symmetricKey: fromHexString('174bc8ab553b4749e4adb4d97ede21ed0f68580b813ac6d4a98160e71219227f')

    ,

    x25519Keypair: {

        privateKey: fromHexString('ecba83b0576a33fa8f2bec8af867edef40905842ba4a4b2781e92746c1d34e0f'),

        publicKey: fromHexString('5d6e0224eadda8aa0fcb29358409f261f97c2df43a3e5cd1800bd3bc3640563c')
    }

    ,

    ed25519Keypair: {

        privateKey: fromHexString('7efa3de63fd50bd1f3c5c4dfe7e8d4068da9f3a9da949e15bc9ea543b07eac0ef360db91d3c124078a2b9d12537f7b902e6fc9cc1dc6f1f3918940e0938c17a2'),

        publicKey: fromHexString('f360db91d3c124078a2b9d12537f7b902e6fc9cc1dc6f1f3918940e0938c17a2')
    }

    ,

    apiAuthKeypair: {

        privateKey: fromHexString('8cf654e90ec260d861c133279bf04a8751ac4d73f32749082c4d4a22d684c2e4eb7ef3d7c012e880674d31f391c1f4c98c316cbf31f85392bf724d49ca743fa9'),

        publicKey: fromHexString('eb7ef3d7c012e880674d31f391c1f4c98c316cbf31f85392bf724d49ca743fa9')
    }
}