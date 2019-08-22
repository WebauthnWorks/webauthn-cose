const crypto    = require('crypto');
const base64url = require('base64url');
const cbor      = require('cbor');
const elliptic  = require('elliptic');
const nodeRSA   = require('node-rsa');

const COSEKEYS = {
    'kty' : 1,
    'alg' : 3,
    'crv' : -1,
    'x'   : -2,
    'y'   : -3,
    'n'   : -1,
    'e'   : -2
}

const COSEKTY = {
    'OKP': 1,
    'EC2': 2,
    'RSA': 3
}

const COSERSASCHEME = {
    '-3': 'pss-sha256',
    '-39': 'pss-sha512',
    '-38': 'pss-sha384',
    '-65535': 'pkcs1-sha1',
    '-257': 'pkcs1-sha256',
    '-258': 'pkcs1-sha384',
    '-259': 'pkcs1-sha512'
}

const COSECRV = {
    '1': 'p256',
    '2': 'p384',
    '3': 'p521'
}

const COSEALGHASH = {
    '-257': 'sha256',
    '-258': 'sha384',
    '-259': 'sha512',
    '-65535': 'sha1',
    '-39': 'sha512',
    '-38': 'sha384',
    '-37': 'sha256',
    '-260': 'sha256',
    '-261': 'sha512',
    '-7': 'sha256',
    '-8': 'sha512',
    '-36': 'sha384',
    '-37': 'sha512'
}

const hash = (alg, message) => {
    return crypto.createHash(alg).update(message).digest();
}

const verifySignature = (signatureBuffer, messageBuffer, cosePublicKeyBuffer) => {
    let pubKeyCose = cbor.decodeAllSync(cosePublicKeyBuffer)[0];
    let hashAlg    = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];

    // Verify ECDSA
    if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
        let x = pubKeyCose.get(COSEKEYS.x);
        let y = pubKeyCose.get(COSEKEYS.y);
        
        let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

        let signatureBaseHash = hash(hashAlg, messageBuffer);

        let ec  = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
        let key = ec.keyFromPublic(ansiKey);

        return key.verify(signatureBaseHash, signatureBuffer);

    // Verify RSA
    } else if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
        let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];

        let key = new nodeRSA(undefined, { signingScheme });
        key.importKey({
            n: pubKeyCose.get(COSEKEYS.n),
            e: 65537,
        }, 'components-public');

        return key.verify(messageBuffer, signatureBuffer);

    // Verify EDDSA
    } else if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
        let x = pubKeyCose.get(COSEKEYS.x);

        let eddsa = new elliptic.eddsa('ed25519');
        let key = eddsa.keyFromPublic(x.toString('hex'))

        return key.verify(messageBuffer, signatureBuffer.toString('hex'))
    }
}

module.exports = { verifySignature }
