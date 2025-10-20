const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');

function createAuthSignature(cerBase64, keyPem, password) {
    console.log('[SIGNATURE] Iniciando creación de firma de autenticación...');

    console.log('[SIGNATURE] Procesando certificado...');
    const { pureCertBase64 } = processCertificate(cerBase64);
    console.log('[SIGNATURE] Certificado procesado. Desencriptando llave privada...');
    const privateKey = decryptPrivateKey(keyPem, password);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
    console.log('[SIGNATURE] Llave privada lista.');

    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60000);
    const createdString = now.toISOString().substring(0, 19) + 'Z';
    const expiresString = expires.toISOString().substring(0, 19) + 'Z';
    const timestampId = `_0`;
    const securityTokenId = `uuid-${uuidv4()}-1`;
    console.log(`[SIGNATURE] Timestamp creado: ${createdString} -> ${expiresString}`);

    const xml = `...`; // El XML es el mismo, no es necesario pegarlo aquí para abreviar.

    console.log('[SIGNATURE] Firmando XML...');
    
    // ****** INICIO DE LA PRUEBA DE TINTA ******
    console.log('[SIGNATURE-V4] Usando constructor de SignedXml con objeto de configuración.');
    const sig = new SignedXml({
      idAttribute: 'u:Id',
      implicitTransforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"]
    });
    // ****** FIN DE LA PRUEBA DE TINTA ******

    sig.signingKey = privateKeyPem;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
    sig.addReference(
        `#${timestampId}`,
        ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );
    
    sig.keyInfoProvider = { /* ... */ };

    sig.computeSignature(xml, { /* ... */ });

    const signedXml = sig.getSignedXml();
    console.log('[SIGNATURE] Firma completada. XML firmado listo.');
    return signedXml;
}

module.exports = { createAuthSignature };
