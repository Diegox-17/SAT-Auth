// /src/services/signature.js

// --- CORRECCIÓN ---
// Se consolidan los 'require' en un solo lugar.
// Se importa 'processCertificate' que será usada por AMBAS funciones.
const { v4: uuidv4 } = require('uuid');
const SignedXml = require('xml-crypto').SignedXml;
const forge = require('node-forge');
const { processCertificate, decryptPrivateKey } = require('../utils/crypto');


//Función de autenticación (Sin cambios, ya funcionaba)
function createAuthSignature(cerBase64, keyPem, password) {
    // ... tu código de autenticación existente y funcional va aquí ...
    // No es necesario pegarlo todo, solo asegúrate de que se quede como está.
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
    
    sig.keyInfoProvider = {
        getKeyInfo: () => `<o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#${securityTokenId}"/></o:SecurityTokenReference>`
    };
    
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
    console.log(`[Signature Service] Iniciando generación de firma para descarga de tipo: ${type}`);
    if (!fiel || !fiel.cerBase64 || !fiel.keyPem || !fiel.password) {
        throw new Error("El objeto 'fiel' y sus propiedades son requeridos.");
    }

    const { cerBase64, keyPem, password } = fiel;
    const { certificate, issuerData, pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    const serviceNode = `des:SolicitaDescarga${type}`;
    
    // --- NUEVO ENFOQUE: Limpio y sin placeholders ---
    // 1. Construir el XML sin ningún bloque de firma.
    const unsignedXml = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
            <s:Header/>
            <s:Body>
                <${serviceNode}>
                    <des:solicitud ${Object.keys(requestData).sort().map(key => `${key}="${requestData[key]}"`).join(' ')}>
                    </des:solicitud>
                </${serviceNode}>
            </s:Body>
        </s:Envelope>
    `.trim();

    console.log('[Signature Service] XML limpio generado. A punto de calcular y adjuntar firma.');
    // console.log(unsignedXml); // Descomentar para ver el XML antes de firmar

    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
    // 2. Definir el KeyInfoProvider para que la firma incluya los datos del certificado.
    sig.keyInfoProvider = {
        getKeyInfo: (key, prefix) => {
            prefix = prefix ? prefix + ':' : '';
            return `<${prefix}X509Data>
                        <${prefix}X509IssuerSerial>
                            <${prefix}X509IssuerName>${issuerData}</${prefix}X509IssuerName>
                            <${prefix}X509SerialNumber>${certificate.serialNumber}</${prefix}X509SerialNumber>
                        </${prefix}X509IssuerSerial>
                        <${prefix}X509Certificate>${pureCertBase64}</${prefix}X509Certificate>
                    </${prefix}X509Data>`;
        }
    };

    // 3. Añadir la referencia usando un XPath robusto, igual que en la autenticación.
    // Esto es mucho más fiable que usar referencias por #Id.
    sig.addReference(
        "//*[local-name(.)='solicitud']", // Referencia al nodo de la solicitud
        [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#"
        ],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );

    // 4. Calcular la firma, especificando el prefijo y la ubicación para inyectarla.
    sig.computeSignature(unsignedXml, {
        prefix: 'xd', // Prefijo para los elementos de la firma (ej: <xd:Signature>)
        location: {
            reference: "//*[local-name(.)='solicitud']", // Inyectar la firma DENTRO del nodo de solicitud
            action: 'append'
        }
    });

    const finalXml = sig.getSignedXml();
    console.log('[Signature Service] Firma generada e inyectada exitosamente. XML listo para enviar.');
    
    return finalXml;
}

module.exports = { createAuthSignature, generateDownloadSignature };
