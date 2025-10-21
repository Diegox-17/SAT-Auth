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
// /src/services/signature.js (solo la función de descarga)
async function generateDownloadSignature(fiel, requestData, type) {
    console.log(`[Signature Service] Iniciando generación de firma para descarga de tipo: ${type}`);
    if (!fiel || !fiel.cerBase64 || !fiel.keyPem || !fiel.password) {
        throw new Error("El objeto 'fiel' y sus propiedades son requeridos.");
    }

    const { cerBase64, keyPem, password } = fiel;
    // Usamos processCertificate para obtener todos los datos necesarios
    const { certificate, issuerData, pureCertBase64 } = processCertificate(cerBase64); 
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    const serviceNode = `des:SolicitaDescarga${type}`;
    const requestId = `id-${forge.util.bytesToHex(forge.random.getBytesSync(20))}`;

    const sortedAttributes = Object.keys(requestData)
        .sort()
        .map(key => `${key}="${requestData[key]}"`)
        .join(' ');
    console.log('[Signature Service] Atributos de la solicitud (ordenados alfabéticamente):', sortedAttributes);
    
    // 1. Construir el XML SIN el bloque de la firma (el método más limpio)
    const unsignedXml = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
            <s:Header/>
            <s:Body>
                <${serviceNode}>
                    <des:solicitud Id="${requestId}" ${sortedAttributes}></des:solicitud>
                </${serviceNode}>
            </s:Body>
        </s:Envelope>
    `.trim();

    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
    // 2. Definir cómo se verá el bloque KeyInfo, usando X509Data como pide el SAT para descargas
    sig.keyInfoProvider = {
        getKeyInfo: () => `<xd:X509Data>
                               <xd:X509IssuerSerial>
                                   <xd:X509IssuerName>${issuerData}</xd:X509IssuerName>
                                   <xd:X509SerialNumber>${certificate.serialNumber}</xd:X509SerialNumber>
                               </xd:X509IssuerSerial>
                               <xd:X509Certificate>${pureCertBase64}</xd:X509Certificate>
                           </xd:X509Data>`
    };

    // 3. Añadir la referencia al nodo que queremos firmar, usando su ID
    sig.addReference(
        `#${requestId}`, // Referencia directa al ID del nodo <des:solicitud>
        [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#"
        ],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );

    console.log('[Signature Service] A punto de calcular la firma final...');

    // 4. Calcular la firma y decirle a la librería EXACTAMENTE dónde inyectarla.
    sig.computeSignature(unsignedXml, {
        prefix: 'xd', // Prefijo para los elementos de la firma (xd:Signature, xd:SignedInfo, etc.)
        location: {
            // El XPath le dice: "Busca el nodo llamado 'solicitud'..."
            reference: `//*[local-name(.)='solicitud']`,
            // "...y añade la firma como el último hijo dentro de él."
            action: 'append'
        }
    });

    const finalXml = sig.getSignedXml();
    console.log('[Signature Service] Firma final generada y colocada correctamente.');
    
    return finalXml;
}

module.exports = { createAuthSignature, generateDownloadSignature };
