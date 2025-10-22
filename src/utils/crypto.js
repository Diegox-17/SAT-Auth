// src/utils/crypto.js

const forge = require('node-forge');

function processCertificate(cerBase64) {
    const cerDer = forge.util.decode64(cerBase64);
    const cerAsn1 = forge.asn1.fromDer(cerDer);
    const certificate = forge.pki.certificateFromAsn1(cerAsn1);

    // --- LA FORMA CORRECTA Y SEGURA DE OBTENER LOS DATOS DEL EMISOR ---
    // Usamos el método de la librería para convertir los atributos a una cadena segura.
    // Esto evita problemas de caracteres especiales y formato.
    const issuerData = certificate.issuer.toString();
    // --- FIN DE LA CORRECCIÓN ---

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
