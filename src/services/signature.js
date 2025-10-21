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
    const { certificate, issuerData, pureCertBase64 } = processCertificate(cerBase64); // Usamos la función correcta
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    const serviceNode = `des:SolicitaDescarga${type}`;
    const requestId = `id-${forge.util.bytesToHex(forge.random.getBytesSync(20))}`;

    const sortedAttributes = Object.keys(requestData)
        .sort()
        .map(key => `${key}="${requestData[key]}"`)
        .join(' ');
    console.log('[Signature Service] Atributos de la solicitud (ordenados alfabéticamente):');
    
    // --- NUEVO ENFOQUE ---
    // 1. Crear el XML con un placeholder para la firma.
    // El namespace 'xd' se define en el sobre para que sea válido en todo el documento.
    const xmlWithPlaceholder = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:xd="http://www.w3.org/2000/09/xmldsig#">
            <s:Header/>
            <s:Body>
                <${serviceNode}>
                    <des:solicitud Id="${requestId}" ${sortedAttributes}>
                        <xd:Signature>
                            <xd:SignedInfo>
                                <xd:CanonicalizationMethod Algorithm="http://www.w.org/2001/10/xml-exc-c14n#"/>
                                <xd:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                                <xd:Reference URI="#${requestId}">
                                    <xd:Transforms>
                                        <xd:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                                    </xd:Transforms>
                                    <xd:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                                    <xd:DigestValue/>
                                </xd:Reference>
                            </xd:SignedInfo>
                            <xd:SignatureValue/>
                            <xd:KeyInfo>
                                <xd:X509Data>
                                    <xd:X509IssuerSerial>
                                        <xd:X509IssuerName>${issuerData}</xd:X509IssuerName>
                                        <xd:X509SerialNumber>${certificate.serialNumber}</xd:X509SerialNumber>
                                    </xd:X509IssuerSerial>
                                    <xd:X509Certificate>${pureCertBase64}</xd:X509Certificate>
                                </xd:X509Data>
                            </xd:KeyInfo>
                        </xd:Signature>
                    </des:solicitud>
                </${serviceNode}>
            </s:Body>
        </s:Envelope>
    `.trim();

    console.log('[Signature Service] XML con placeholder generado.:',xmlWithPlaceholder);
                
    console.log('A punto de calcular la firma.');

    // 2. Usar la librería para "rellenar" los valores de la firma.
    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    
    // NOTA: Con este método, no necesitamos 'signatureAlgorithm', 'keyInfoProvider', etc.,
    // porque ya están definidos en el placeholder del XML.
    
    // La referencia ahora es al nodo <Signature> mismo.
    sig.addReference("//*[local-name(.)='SignedInfo']");
    
    // 3. Calcular la firma sobre el XML que ya contiene la estructura.
    sig.computeSignature(xmlWithPlaceholder);

    // 4. Obtener el XML final con los valores de DigestValue y SignatureValue calculados.
    const finalXml = sig.getSignedXml();

    console.log('[Signature Service] Firma generada y rellenada exitosamente. XML listo para enviar.');
    console.log('el XML final es: ',finalXml);
    // console.log(finalXml); // Descomenta para depuración final si es necesario

    return finalXml;
}

module.exports = { createAuthSignature, generateDownloadSignature };
