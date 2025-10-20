// ... (los require al principio se mantienen igual)
const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');

function createAuthSignature(cerBase64, keyPem, password) {
    console.log('[SIGNATURE] Iniciando creación de firma de autenticación...');

    // ... (toda la lógica de certificados y timestamps se mantiene igual)
    const { pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60000);
    const createdString = now.toISOString().substring(0, 19) + 'Z';
    const expiresString = expires.toISOString().substring(0, 19) + 'Z';
    const timestampId = `_0`;
    const securityTokenId = `uuid-${uuidv4()}-1`;
    console.log(`[SIGNATURE] Timestamp creado: ${createdString} -> ${expiresString}`);

    const xml = `...`; // El XML es el mismo, no es necesario pegarlo aquí para abreviar.

    console.log('[SIGNATURE] Firmando XML...');
    
    // El constructor se mantiene corregido
    const sig = new SignedXml({
      idAttribute: 'u:Id',
      implicitTransforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"]
    });

    sig.signingKey = privateKeyPem;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
    // ****** INICIO DE LA CORRECCIÓN FINAL ******
    // En lugar de referenciar el ID, usamos un XPath que ignora los namespaces.
    // Esto busca cualquier elemento llamado 'Timestamp' en todo el documento.
    const xpath = "//*[local-name(.)='Timestamp']";
    sig.addReference(
        xpath,
        ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );
    // ****** FIN DE LA CORRECCIÓN FINAL ******
    
    sig.keyInfoProvider = { /* ... sin cambios ... */ };

    sig.computeSignature(xml, { /* ... sin cambios ... */ });

    const signedXml = sig.getSignedXml();
    console.log('[SIGNATURE] Firma completada. XML firmado listo.');
    return signedXml;
}

module.exports = { createAuthSignature };
