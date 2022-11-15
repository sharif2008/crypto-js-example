
var forge = require('node-forge');
const fs = require('fs');
const Buffer = require('node:buffer');


export const createKeypair = () => {

    console.log('Key generation started---');

    var rsa = forge.pki.rsa;

    // generate an RSA key pair synchronously
    // *NOT RECOMMENDED*: Can be significantly slower than async and may block
    // JavaScript execution. Will use native Node.js 10.12.0+ API if possible.
    var keypair = rsa.generateKeyPair(2048);

    /*     // generate an RSA key pair asynchronously (uses web workers if available)
        // use workers: -1 to run a fast core estimator to optimize # of workers
        // *RECOMMENDED*: Can be significantly faster than sync. Will use native
        // Node.js 10.12.0+ or WebCrypto API if possible.
        rsa.generateKeyPair({ bits: 2048, workers: 2 }, function (err, keypair) {
            // keypair.privateKey, keypair.publicKey
        }); */

    // generate an RSA key pair in steps that attempt to run for a specified period
    // of time on the main JS thread
    /*    var state = rsa.createKeyPairGenerationState(2048, 0x10001);
       var step = function () {
           // run for 100 ms
           if (!rsa.stepKeyPairGenerationState(state, 100)) {
               setTimeout(step, 1);
           }
           else {
               // done, turn off progress indicator, use state.keys
           }
       };
       // turn on progress indicator, schedule generation to run
       setTimeout(step); */

    // sign data with a private key and output DigestInfo DER-encoded bytes
    // (defaults to RSASSA PKCS#1 v1.5)
    var md = forge.md.sha1.create();
    md.update('sign this', 'utf8');

    let privateKey = keypair.privateKey;
    console.log(privateKey);
    let publicKey = keypair.publicKey;

    var signature = privateKey.sign(md);

    // verify data with a public key
    // (defaults to RSASSA PKCS#1 v1.5)
    var verified = publicKey.verify(md.digest().bytes(), signature);
    console.log('is verified? ' + verified);

    // sign data using RSASSA-PSS where PSS uses a SHA-1 hash, a SHA-1 based
    // masking function MGF1, and a 20 byte salt

    console.log("key generated end")
    //
}

export const createNodeCrypto =  async () => {
	const {
	  generateKeyPairSync,
	  createSign,
	  createVerify,
	  KeyObject,
	} = require('node:crypto');

	const { privateKey, publicKey } = generateKeyPairSync('ec', {
	  namedCurve: 'sect239k1'
	});

	console.log(publicKey);

	const sign = createSign('SHA256');
	sign.write('some data to sign');
	sign.end();
	const signature = sign.sign(privateKey, 'hex');

	const verify = createVerify('SHA256');
	verify.write('some data to sign');
	verify.end();
	console.log(verify.verify(publicKey, signature, 'hex'));
} 

createNodeCrypto();