const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');

function createAuthSignature(cerBase64, keyPem, password) {
    console.log('[SIGNATURE] v5.1 - Ejecutando función createAuthSignature.');

    let pureCertBase64, privateKey, privateKeyPem;
    try {
        console.log('[SIGNATURE]   - Paso 1.1: Procesando certificado...');
        const certData = processCertificate(cerBase64);
        pureCertBase64 = certData.pureCertBase64;
        console.log('[SIGNATURE]   - Paso 1.1: ¡Éxito!');

        console.log('[SIGNATURE]   - Paso 1.2: Desencriptando llave privada...');
        privateKey = decryptPrivateKey(keyPem, password);
        privateKeyPem = forge.pki.privateKeyToPem(privateKey);
        console.log('[SIGNATURE]   - Paso 1.2: ¡Éxito!');
    } catch (e) {
        console.error('[SIGNATURE]   - ERROR en el procesamiento de credenciales:', e.message);
        throw e;
    }

    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60000);
    const createdString = now.toISOString().substring(0, 19) + 'Z';
    const expiresString = expires.toISOString().substring(0, 19) + 'Z';
    const timestampId = `_0`;
    const securityTokenId = `uuid-${uuidv4()}-1`;
    console.log(`[SIGNATURE]   - Paso 2: Timestamps generados: ${createdString} -> ${expiresString}`);

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
    console.log('[SIGNATURE]   - Paso 3: Plantilla XML generada.');

    try {
        console.log('[SIGNATURE]   - Paso 4: Iniciando firma con xml-crypto...');
        const sig = new SignedXml();
        sig.signingKey = privateKeyPem;
        sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

        const transforms = ["http://www.w3.org/2001/10/xml-exc-c14n#"];
        const digestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";
        
        // La referencia más explícita posible
        const xpath = "//*[local-name(.)='Timestamp' and namespace-uri(.)='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']";
        sig.addReference(xpath, transforms, digestAlgorithm);

        sig.keyInfoProvider = {
            getKeyInfo: (key, prefix) => {
                return `<${prefix}:SecurityTokenReference><${prefix}:Reference URI="#${securityTokenId}" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/></${prefix}:SecurityTokenReference>`;
            }
        };

        console.log('[SIGNATURE]   - Paso 4.1: Calculando firma...');
        sig.computeSignature(xml, {
            prefix: 'o',
            location: { reference: "//*[local-name(.)='Security']", action: 'append' }
        });
        
        const signedXml = sig.getSignedXml();
        console.log('[SIGNATURE]   - Paso 4.2: ¡Éxito! Firma calculada.');
        return signedXml;
    } catch (e) {
        console.error('[SIGNATURE]   - ERROR en el proceso de firma de xml-crypto:', e);
        throw e;
    }
}

module.exports = { createAuthSignature };
