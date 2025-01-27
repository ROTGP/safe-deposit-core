import { PasswordHashingEffort } from '../../src/safeDeposit'
import { TestUser } from './../../src/types'

const fromHexString = (hexString: string) => Uint8Array.from(hexString.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));

// Person A
export const alice: TestUser = {

    uuid: fromHexString('51b4d0ef7e43c561e8a25912f82b1bfa')

    ,

    passphrase: "O say can you see by the dawn’s early light"

    ,

    emailAddresses: ['alice.bradbury@cooper.com']

    ,

    QRCode: fromHexString('51b4d0ef7e43c561e8a25912f82b1bfa000000cf81899e5cc8f61527d01da70043e579e05981a66ec239b153f978b013c37b844b64ab50e7f74bb9a8a9747f59209821aad9d79bf340e35e4e1371')

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

    uuid: fromHexString('dd7194a14738f1930e81cee691de3ebb')

    ,

    passphrase: 'too many secret$'

    ,

    emailAddresses: ['bob.smith@gmail.com']

    ,

    QRCode: fromHexString('dd7194a14738f1930e81cee691de3ebb0000013ad7ab04434f2350879bd42aa3000ac6959cce5930c8b3d286ce1b3ef5f2694cf9b1c37d842ad4b12593f3c92ce89f283f87adea14d2324b65c820')

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

    uuid: fromHexString('a2210baa2a9aef5c73f65fa195bcf185')

    ,

    passphrase: 'bigBlueShark-44'

    ,

    emailAddresses: []

    ,

    QRCode: fromHexString('a2210baa2a9aef5c73f65fa195bcf185000000e096f24cc11fa13baccac783ddfe10c63228b7292af4ac27a4257ac67e7c3e5f457793b5506682441d4542080bda59a254033f2d77317e39315071')

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

    uuid: fromHexString('b17dcb21c62d0745fdb08d4c3bd5cc6d')

    ,

    passphrase: 'qwertyuiop'

    ,

    emailAddresses: ['bad-intentions@up-to-no-good.com']

    ,

    QRCode: fromHexString('b17dcb21c62d0745fdb08d4c3bd5cc6d0000017de0938fa4ece9b86ae554131031f91c19edde13da895fd1a24e07d4a08f6e876fec2f6852d4847d46410388c2e2004174ee28bcd4f1dab4ffc6aa')

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

    uuid: fromHexString('ae9904cae536a0cf35e614a11ccc7073')

    ,

    passphrase: 'RaiñbowT@ble_7!'

    ,

    emailAddresses: []

    ,

    QRCode: fromHexString('ae9904cae536a0cf35e614a11ccc7073000000059cebbf5264c7cd4fca5e4f0c6873a902a21639db3d6fd5a7b8a94a78b8b303f1de6825572b86c6fe25ebc953e0ca1526d4e2b9c8a352a5e4b295')

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