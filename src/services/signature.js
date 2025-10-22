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
    //console.log('[SIGNATURE] v10.0 - Sintaxis final para xml-crypto@2.1.3');

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
    console.log(`[Signature Service vFINAL] Iniciando firma de SOLICITUD tipo: ${type}`);
    if (!fiel || !fiel.cerBase64 || !fiel.keyPem || !fiel.password) {
        throw new Error("El objeto 'fiel' y sus propiedades son requeridos.");
    }

    // 1. Conservamos toda tu lógica inicial de preparación
    const { cerBase64, keyPem, password } = fiel;
    const { pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    const serviceNode = `des:SolicitaDescarga${type}`;
    const attributesString = Object.keys(requestData).sort().map(key => `${key}="${requestData[key]}"`).join(' ');
    const soapBody = `<${serviceNode} xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"><des:solicitud ${attributesString}></des:solicitud></${serviceNode}>`.trim();

    // 3. La configuración de la firma es idéntica
    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.keyInfoProvider = {
        getKeyInfo: () => `<X509Data><X509Certificate>${pureCertBase64}</X509Certificate></X509Data>`
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

// --- FUNCIÓN DE VERIFICACIÓN - ALINEADA CON LA DE SOLICITUD ---
async function signVerificationRequest(fiel, idSolicitud, rfcSolicitante) {
    console.log(`[Signature Service vFINAL] Iniciando firma de VERIFICACIÓN`);
    const { cerBase64, keyPem, password } = fiel;
    const { pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    const soapBody = `<des:VerificaSolicitudDescarga xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"><des:solicitud IdSolicitud="${idSolicitud}" RfcSolicitante="${rfcSolicitante}"></des:solicitud></des:VerificaSolicitudDescarga>`.trim();
    
    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.keyInfoProvider = {
        getKeyInfo: () => 
            `<X509Data>
                <X509Certificate>${pureCertBase64}</X509Certificate>
            </X509Data>` };
    sig.addReference("//*[local-name(.)='solicitud']", 
        ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", 
        "http://www.w3.org/2001/10/xml-exc-c14n#"], 
                    "http://www.w3.org/2000/09/xmldsig#sha1");
    sig.computeSignature(soapBody, { 
        prefix: 'xd', location: { 
            reference: "//*[local-name(.)='solicitud']", action: 'append' 
        } 
    });

    const signedBodyXml = sig.getSignedXml();
    const finalXml = 
        `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
            <s:Header/>
            <s:Body>${signedBodyXml}</s:Body>
        </s:Envelope>`;
    return finalXml;
}

// --- FUNCIÓN DE DESCARGA DE PAQUETES - ALINEADA CON LA DE SOLICITUD ---
async function signPackageDownloadRequest(fiel, idPaquete, rfcSolicitante) {
    console.log(`[Signature Service vFINAL] Iniciando firma de DESCARGA DE PAQUETE`);
    const { cerBase64, keyPem, password } = fiel;
    const { pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const pemPrivateKey = forge.pki.privateKeyToPem(privateKey);

    const soapBody = `<des:PeticionDescargaMasivaTercerosEntrada xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"><des:peticionDescarga IdPaquete="${idPaquete}" RfcSolicitante="${rfcSolicitante}"></des:peticionDescarga></des:PeticionDescargaMasivaTercerosEntrada>`.trim();

    const sig = new SignedXml();
    sig.signingKey = pemPrivateKey;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.keyInfoProvider = { getKeyInfo: () => 
        `<X509Data>
            <X509Certificate>${pureCertBase64}</X509Certificate>
        </X509Data>` };
    sig.addReference("//*[local-name(.)='peticionDescarga']", 
            ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", 
            "http://www.w3.org/2001/10/xml-exc-c14n#"], 
            "http://www.w3.org/2000/09/xmldsig#sha1");
    sig.computeSignature(soapBody, { prefix: 'xd', location: { reference: "//*[local-name(.)='peticionDescarga']", action: 'append' } });
    
    const signedBodyXml = sig.getSignedXml();
    const finalXml = 
        `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
            <s:Header/>
            <s:Body>${signedBodyXml}</s:Body>
        </s:Envelope>`;
    return finalXml;
}

module.exports = { createAuthSignature, generateDownloadSignature, signVerificationRequest, signPackageDownloadRequest };
