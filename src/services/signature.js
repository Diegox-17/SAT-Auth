//Constantes para función de autenticación:
const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');

//Constantes para función de descargas:
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
async function generateDownloadSignature(fiel, requestData, type) {
    if (!fiel || !fiel.cerBase64 || !fiel.keyPem || !fiel.password) {
        throw new Error("El objeto 'fiel' y sus propiedades son requeridos.");
    }
    
    const { cerBase64, keyPem, password } = fiel;
    const { certificate, issuerData } = getCertificateInfo(cerBase64);
    const privateKey = forge.pki.decryptRsaPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    const serviceNode = `des:SolicitaDescarga${type}`;
    const requestId = `id-${forge.util.bytesToHex(forge.random.getBytesSync(20))}`;

    // CRÍTICO: Ordenar atributos alfabéticamente
    const sortedAttributes = Object.keys(requestData)
        .sort()
        .map(key => `${key}="${requestData[key]}"`)
        .join(' ');
    
    // El nodo <des:solicitud> con sus atributos ordenados
    const solicitudNode = `<des:solicitud Id="${requestId}" ${sortedAttributes}></des:solicitud>`;

    // Construir el XML base que será firmado
    const unsignedXml = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:xd="http://www.w3.org/2000/09/xmldsig#">
            <s:Header/>
            <s:Body>
                <${serviceNode}>
                    ${solicitudNode}
                </${serviceNode}>
            </s:Body>
        </s:Envelope>
    `.trim();

    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.keyInfoProvider = {
        getKeyInfo: () => `<xd:X509Data>
                               <xd:X509IssuerSerial>
                                   <xd:X509IssuerName>${issuerData}</xd:X509IssuerName>
                                   <xd:X509SerialNumber>${certificate.serialNumber}</xd:X509SerialNumber>
                               </xd:X509IssuerSerial>
                               <xd:X509Certificate>${cerBase64}</xd:X509Certificate>
                           </xd:X509Data>`
    };

    sig.addReference(
        `#${requestId}`, // Referencia al ID del nodo <des:solicitud>
        [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#"
        ],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );

    // Ubicación donde se insertará la firma
    sig.computeSignature(unsignedXml, {
        location: {
            reference: `//*[local-name(.)='solicitud']`,
            action: 'append'
        }
    });

    return sig.getSignedXml();
}

module.exports = { createAuthSignature,generateDownloadSignature };
