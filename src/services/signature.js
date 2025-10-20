const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');

function createAuthSignature(cerBase64, keyPem, password) {
    console.log('[SIGNATURE] v10.0 - Sintaxis final para xml-crypto@2.1.3');

    const { pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60000);
    const createdString = now.toISOString().substring(0, 19) + 'Z';
    const expiresString = expires.toISOString().substring(0, 19) + 'Z';
    const timestampId = `_0`;
    const securityTokenId = `uuid-${uuidv4()}-1`;
    console.log(`[SIGNATURE] Timestamps: ${createdString} -> ${expiresString}`);

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

    console.log('[SIGNATURE] Firmando XML...');
    const sig = new SignedXml();
    sig.signingKey = privateKeyPem;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
    // El KeyInfoProvider debe definir su propio namespace si no se define globalmente
    sig.keyInfoProvider = {
        getKeyInfo: () => `<o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#${securityTokenId}"/></o:SecurityTokenReference>`
    };
    
    // Usamos el XPath robusto que es nuestra mejor opción para evitar el error InvalidSecurity
    const xpath = "//*[local-name(.)='Timestamp']";
    const transforms = ["http://www.w3.org/2001/10/xml-exc-c14n#"];
    const digestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";

    sig.addReference(xpath, transforms, digestAlgorithm);

    sig.computeSignature(xml, { 
        prefix: 'o', 
        location: { reference: "//*[local-name()='Security']", action: 'append' } 
    });
    
    console.log('[SIGNATURE] Firma completada.');
    return sig.getSignedXml();
}

module.exports = { createAuthSignature };
