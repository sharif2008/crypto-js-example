import * as asn1js from 'asn1js';
import WebCrypto = require('node-webcrypto-ossl');
import {
  getCrypto, CryptoEngine,
  setEngine, getAlgorithmParameters, CertificationRequest, AttributeTypeAndValue
} from 'pkijs/build'
import { arrayBufferToString, toBase64 } from 'pvutils';
import * as nodeSpecificCrypto from './node-crypto';

//https://github.com/PeculiarVentures/PKI.js/blob/31c10e9bb879cac59d710102adf4fd7bd61cd66c/src/CryptoEngine.js#L1300
const hashAlg = 'SHA-256'
const signAlg = 'ECDSA'


const webcrypto = new WebCrypto();

setEngine('nodeEngine', nodeSpecificCrypto, new CryptoEngine({
  crypto: nodeSpecificCrypto,
  subtle: webcrypto.subtle,
  name: 'nodeEngine'
}));

/**
 * @example 
 * createPKCS10({ enrollmentID: 'user1', organizationUnit: 'Marketing', organization: 'Farmer Market', state: 'M', country: 'V' })
 *  .then(({csr, privateKey} => {...}))
 */

export async function createPKCS10({ enrollmentID, organizationUnit, organization, state, country }) {
  const crypto = getWebCrypto()


  const keyPair = await generateKeyPair(crypto, getAlgorithm(signAlg, hashAlg))



  let result = {
    csr: `-----BEGIN CERTIFICATE REQUEST-----\n${formatPEM(
      toBase64(
        arrayBufferToString(
          await createCSR(keyPair, hashAlg, { enrollmentID, organizationUnit, organization, state, country })
        )
      )
    )}\n-----END CERTIFICATE REQUEST-----`,
    privateKey: `-----BEGIN PRIVATE KEY-----\n${toBase64(arrayBufferToString(await crypto.exportKey('pkcs8', keyPair.privateKey)))
      }\n-----END PRIVATE KEY-----`
  }

  console.log(result.privateKey);

  return result;
}

async function createCSR(keyPair, hashAlg, { enrollmentID, organizationUnit, organization, state, country }) {
  const pkcs10 = new CertificationRequest()
  pkcs10.version = 0
  //list of OID reference: http://oidref.com/2.5.4
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.6', //countryName
    value: new asn1js.PrintableString({ value: country })
  }))
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.8', //stateOrProvinceName
    value: new asn1js.Utf8String({ value: state })
  }))
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.10', //organizationName
    value: new asn1js.Utf8String({ value: organization })
  }))
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.11', //organizationUnitName
    value: new asn1js.Utf8String({ value: organizationUnit })
  }))
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.3', //commonName
    value: new asn1js.Utf8String({ value: enrollmentID })
  }))

  //add attributes to make CSR valid
  //Attributes must be "a0:00" if empty
  pkcs10.attributes = []

  await pkcs10.subjectPublicKeyInfo.importKey(keyPair.publicKey)
  //signing final PKCS#10 request
  await pkcs10.sign(keyPair.privateKey, hashAlg)

  return pkcs10.toSchema().toBER(false)
}

// add line break every 64th character
function formatPEM(pemString) {
  return pemString.replace(/(.{64})/g, '$1\n')
}

function getWebCrypto() {
  const crypto = getCrypto()
  if (typeof crypto === 'undefined')
    throw 'No WebCrypto extension found'
  return crypto
}

function getAlgorithm(signAlg, hashAlg) {
  const algorithm = getAlgorithmParameters(signAlg, 'generatekey')
  if ('hash' in algorithm.algorithm)
    algorithm.algorithm.hash.name = hashAlg
  return algorithm
}

function generateKeyPair(crypto, algorithm) {
  return crypto.generateKey(algorithm.algorithm, true, algorithm.usages)
}



let result = createPKCS10({ enrollmentID: "a", organization: "b", country: "c", organizationUnit: "d", state: "e" });
/**
 * to learn more about asn1, ber & der, attributes & types used in pkcs#10
 * http://luca.ntop.org/Teaching/Appunti/asn1.html
 * 
 * guides to SubtleCrypto (which PKIjs is built upon):
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
 */