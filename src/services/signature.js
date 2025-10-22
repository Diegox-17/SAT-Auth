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

    // 1. Conservamos toda tu lógica inicial de preparación
    const { cerBase64, keyPem, password } = fiel;
    const { certificate, issuerData, pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    const attributesString = Object.keys(requestData).sort()
        .map(key => `${key}="${requestData[key]}"`)
        .join(' ');
    
    // --- LA CORRECCIÓN ESTRUCTURAL ---
    // 2. Creamos solo el CUERPO del XML que será firmado (sin el sobre <s:Envelope>)
    const serviceNode = `des:SolicitaDescarga${type}`;
    const soapBody = `
        <${serviceNode} xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
            <des:solicitud ${attributesString}>
            </des:solicitud>
        </${serviceNode}>
    `.trim();

    // 3. La configuración de la firma es idéntica
    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
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

    sig.addReference(
        "//*[local-name(.)='solicitud']",
        ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );

    // 4. Calculamos la firma sobre el CUERPO, no sobre el sobre completo
    sig.computeSignature(soapBody, {
        prefix: 'xd',
        location: {
            reference: "//*[local-name(.)='solicitud']",
            action: 'append'
        }
    });

    // 5. Obtenemos el cuerpo ya firmado
    const signedBodyXml = sig.getSignedXml();

    // 6. Envolvemos el cuerpo firmado en el sobre final, igual que en signAuthRequest
    const finalXml = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
            <s:Header/>
            <s:Body>
                ${signedBodyXml}
            </s:Body>
        </s:Envelope>
    `.trim();
    
    console.log('[Signature Service] Firma generada y XML envuelto exitosamente.');
    return finalXml;
}

async function signVerificationRequest(fiel, idSolicitud, rfcSolicitante) {
    console.log(`[Signature Service] Iniciando firma para Verificación de Solicitud`);
    const { cerBase64, keyPem, password } = fiel;

    // 1. Reutilizamos exactamente la misma lógica de preparación de datos que ya funciona
    const { certificate, issuerData, pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    // 2. Construimos el cuerpo SOAP específico para la verificación
    const soapBody = `
        <des:VerificaSolicitudDescarga xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
            <des:solicitud IdSolicitud="${idSolicitud}" RfcSolicitante="${rfcSolicitante}">
            </des:solicitud>
        </des:VerificaSolicitudDescarga>
    `.trim();

    // 3. Clonamos la configuración de firma de generateDownloadSignature
    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"; // Algoritmo explícito
    
    // KeyInfoProvider idéntico
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

    // Referencia y Transforms idénticos
    sig.addReference(
        "//*[local-name(.)='solicitud']",
        [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#"
        ],
        "http://www.w3.org/2000/09/xmldsig#sha1" // Digest idéntico
    );

    // 4. Calculamos la firma sobre el cuerpo del XML
    sig.computeSignature(soapBody, {
        prefix: 'xd', // Usamos el mismo prefijo
        location: {
            reference: "//*[local-name(.)='solicitud']",
            action: 'append'
        }
    });

    const signedBodyXml = sig.getSignedXml();

    // 5. Envolvemos el cuerpo firmado en el sobre final
    const finalXml = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
            <s:Header/>
            <s:Body>
                ${signedBodyXml}
            </s:Body>
        </s:Envelope>
    `.trim();

    console.log('[Signature Service] Firma de Verificación generada exitosamente.');
    return finalXml;
}

//función para la descarga de paquetes
async function signPackageDownloadRequest(fiel, idPaquete, rfcSolicitante) {
    console.log(`[Signature Service] Iniciando firma para descarga del paquete: ${idPaquete}`);
    const { cerBase64, keyPem, password } = fiel;

    const { certificate, issuerData, pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    // 1. Construimos el cuerpo SOAP específico para la descarga de paquetes
    const soapBody = `
        <des:PeticionDescargaMasivaTercerosEntrada xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
            <des:peticionDescarga IdPaquete="${idPaquete}" RfcSolicitante="${rfcSolicitante}">
            </des:peticionDescarga>
        </des:PeticionDescargaMasivaTercerosEntrada>
    `.trim();

    // 2. La configuración de la firma es idéntica a las otras que ya funcionan
    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
    // KeyInfoProvider idéntico
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

    sig.addReference(
        "//*[local-name(.)='peticionDescarga']", // Firmamos el nodo 'peticionDescarga'
        ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );

    // 4. Calculamos la firma sobre el cuerpo del XML
    sig.computeSignature(soapBody, {
        prefix: 'xd', // Usamos el mismo prefijo
        location: {
            reference: "//*[local-name(.)='peticionDescarga']",
            action: 'append'
        }
    });
    
    const signedBodyXml = sig.getSignedXml();

    // 3. Envolvemos en el sobre final
    const finalXml = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header/><s:Body>${signedBodyXml}</s:Body></s:Envelope>`;

    console.log('[Signature Service] Firma de descarga de paquete generada exitosamente.');
    return finalXml;
}

module.exports = { createAuthSignature, generateDownloadSignature, signVerificationRequest, signPackageDownloadRequest };
