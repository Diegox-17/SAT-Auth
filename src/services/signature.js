//Constantes para función de autenticación:
const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');

//Constantes para función de descargas:
const { SignedXml } = require('xml-crypto');
const { getCertificateInfo } = require('../utils/crypto');

//Función de autenticación
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
                <Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"/>
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

//Función de descargas:
/**
 * Genera el XML firmado para las solicitudes de descarga de CFDI.
 * @param {object} fiel - Objeto con credenciales de la FIEL.
 * @param {object} requestData - Parámetros para la solicitud (fechas, RFCs, etc.).
 * @param {string} type - 'issued' o 'received'.
 * @returns {string} El sobre SOAP completo y firmado.
 */
async function generateDownloadSignature(fiel, requestData, type) {
    const { cerBase64, keyPem, password } = fiel;
    const { certificate, issuerData } = getCertificateInfo(cerBase64);

    // Obtener la llave privada
    const privateKey = forge.pki.decryptRsaPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    // Determinar el tipo de solicitud y sus parámetros
    const serviceNode = type === 'issued' ? 'des:SolicitaDescargaEmitidos' : 'des:SolicitaDescargaRecibidos';
    const rfcNode = type === 'issued' 
        ? `<des:RfcReceptores>${requestData.rfcReceptores.map(r => `<des:RfcReceptor>${r}</des:RfcReceptor>`).join('')}</des:RfcReceptores>`
        : ''; // Para recibidos, el RFC emisor es un atributo.

    // CRÍTICO: Ordenar los atributos de la solicitud alfabéticamente
    const sortedAttributes = Object.keys(requestData)
        .filter(key => typeof requestData[key] === 'string') // Solo atributos simples
        .sort()
        .map(key => `${key}="${requestData[key]}"`)
        .join(' ');
        
    const requestId = `id-${forge.util.bytesToHex(forge.random.getBytesSync(20))}`;

    const soapBodyContent = `
        <${serviceNode}>
            <des:solicitud ${sortedAttributes} Id="${requestId}">
                ${rfcNode}
            </des:solicitud>
        </${serviceNode}>
    `;

    // XML completo sin firma para ser procesado
    const unsignedXml = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
            <s:Header/>
            <s:Body>
                ${soapBodyContent}
            </s:Body>
        </s:Envelope>
    `;

    // Lógica de firma
    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    sig.addReference(
        `#${requestId}`, // Referencia al ID de la solicitud
        ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
        'http://www.w3.org/2000/09/xmldsig#sha1'
    );
    
    sig.keyInfoProvider = {
        getKeyInfo: () => `<X509Data>
                            <X509IssuerSerial>
                                <X509IssuerName>${issuerData}</X509IssuerName>
                                <X509SerialNumber>${certificate.serialNumber}</X509SerialNumber>
                            </X509IssuerSerial>
                            <X509Certificate>${cerBase64}</X509Certificate>
                        </X509Data>`
    };

    sig.computeSignature(unsignedXml, {
        prefix: 'xd',
        location: { reference: `//*[local-name(.)='solicitud']`, action: 'append' }
    });

    return sig.getSignedXml();
}

module.exports = { createAuthSignature,generateDownloadSignature };
