const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
// ****** INICIO DE LA CORRECCIÓN ******
// Esta línea es la que faltaba y causaba el error '... is not defined'.
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');
// ****** FIN DE LA CORRECCIÓN ******

/**
 * Crea el sobre SOAP firmado para la autenticación en el SAT.
 * @param {string} cerBase64 - El contenido del archivo .cer en Base64.
 * @param {string} keyPem - El contenido del archivo .key en formato PEM.
 * @param {string} password - La contraseña de la FIEL.
 * @returns {string} El XML del sobre SOAP completo y firmado.
 */
function createAuthSignature(cerBase64, keyPem, password) {
    console.log('[SIGNATURE] Iniciando creación de firma de autenticación...');

    // 1. Procesar certificados y llaves
    console.log('[SIGNATURE] Procesando certificado...');
    const { pureCertBase64 } = processCertificate(cerBase64);
    console.log('[SIGNATURE] Certificado procesado. Desencriptando llave privada...');
    const privateKey = decryptPrivateKey(keyPem, password);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
    console.log('[SIGNATURE] Llave privada lista.');

    // 2. Generar Timestamps y UUIDs
    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60000); // 5 minutos de validez
    const createdString = now.toISOString().substring(0, 19) + 'Z';
    const expiresString = expires.toISOString().substring(0, 19) + 'Z';
    const timestampId = `_0`;
    const securityTokenId = `uuid-${uuidv4()}-1`;
    console.log(`[SIGNATURE] Timestamp creado: ${createdString} -> ${expiresString}`);

    // 3. Construir el XML base (sin firmar)
    const xml = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <s:Header>
                <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <u:Timestamp u:Id="${timestampId}">
                        <u:Created>${createdString}</u:Created>
                        <u:Expires>${expiresString}</u:Expires>
                    </u:Timestamp>
                    <o:BinarySecurityToken u:Id="${securityTokenId}" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${pureCertBase64}</o:BinarySecurityToken>
                </o:Security>
            </s:Header>
            <s:Body>
                <Autentica xmlns="http://DescargaMasivaTerceros.gob.mx/"/>
            </s:Body>
        </s:Envelope>
    `;
    console.log('[SIGNATURE] Plantilla XML generada.');

    // 4. Firmar el XML
    console.log('[SIGNATURE] Firmando XML...');
    const sig = new SignedXml(null, {
      idAttribute: 'u:Id',
      implicitTransforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"]
    });

    sig.signingKey = privateKeyPem;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
    sig.addReference(
        `#${timestampId}`,
        ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );
    
    sig.keyInfoProvider = {
        getKeyInfo: () => {
            return `<o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#${securityTokenId}"/></o:SecurityTokenReference>`;
        }
    };

    sig.computeSignature(xml, {
        prefix: 'o',
        location: {
            reference: "//*[local-name()='Security']",
            action: 'append'
        }
    });

    const signedXml = sig.getSignedXml();
    console.log('[SIGNATURE] Firma completada. XML firmado listo.');
    return signedXml;
}

// Asegurémonos de que la exportación es correcta
module.exports = { createAuthSignature };
