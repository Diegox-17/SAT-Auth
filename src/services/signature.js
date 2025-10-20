const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');

/**
 * Crea el sobre SOAP firmado para la autenticación en el SAT.
 * @param {string} cerBase64 - El contenido del archivo .cer en Base64.
 * @param {string} keyPem - El contenido del archivo .key en formato PEM.
 * @param {string} password - La contraseña de la FIEL.
 * @returns {string} El XML del sobre SOAP completo y firmado.
 */
function createAuthSignature(cerBase64, keyPem, password) {
    // 1. Procesar certificados y llaves
    const { pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

    // 2. Generar Timestamps y UUIDs
    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60000); // 5 minutos de validez
    const createdString = now.toISOString().substring(0, 19) + 'Z';
    const expiresString = expires.toISOString().substring(0, 19) + 'Z';
    const timestampId = `_0`;
    const securityTokenId = `uuid-${uuidv4()}-1`;

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

    // 4. Firmar el XML
    const sig = new SignedXml();
    sig.signingKey = privateKeyPem;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.addReference(
        `//*[@u:Id='${timestampId}']`, // XPath para seleccionar el Timestamp
        ["http://www.w3.org/2001/10/xml-exc-c14n#"], // Transformación de canonización exclusiva
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );
    
    // Agregamos la información del certificado a la firma
    sig.keyInfoProvider = {
        getKeyInfo: () => {
            return `<o:SecurityTokenReference><o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#${securityTokenId}"/></o:SecurityTokenReference>`;
        }
    };

    sig.computeSignature(xml, {
        prefix: 'o', // Prefijo para los elementos de Security (o:Security, o:BinarySecurityToken)
        location: {
            reference: "//*[local-name()='Security']", // Dónde insertar la firma
            action: 'append'
        }
    });

    return sig.getSignedXml();
}

module.exports = { createAuthSignature };