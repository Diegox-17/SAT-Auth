// src/utils/crypto.js

const forge = require('node-forge');

function processCertificate(cerBase64) {
    const cerDer = forge.util.decode64(cerBase64);
    const cerAsn1 = forge.asn1.fromDer(cerDer);
    const certificate = forge.pki.certificateFromAsn1(cerAsn1);

    // --- LÓGICA ARMONIZADA Y ROBUSTA ---
    // Genera una cadena de emisor estándar y limpia, aceptada por todos los servicios.
    const issuerAttributes = certificate.issuer.attributes;
    const issuerData = issuerAttributes.map(attr => {
        const shortName = attr.shortName || attr.name;
        return `${shortName}=${attr.value}`;
    }).join(', ');
    // --- FIN DE LA LÓGICA ---

    const certificatePem = forge.pki.certificateToPem(certificate);
    const pureCertBase64 = certificatePem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/\r/g, '')
        .replace(/\n/g, '');

    return { certificate, issuerData, pureCertBase64 };
}

function decryptPrivateKey(keyPem, password) {
    try {
        const privateKey = forge.pki.decryptRsaPrivateKey(keyPem, password);
        if (!privateKey) {
             throw new Error("La contraseña de la FIEL es incorrecta o el archivo .key está dañado.");
        }
        return privateKey;
    } catch (e) {
        throw new Error("La contraseña de la FIEL es incorrecta. Verifíquela.");
    }
}

module.exports = { processCertificate, decryptPrivateKey };
