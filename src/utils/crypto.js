// src/utils/crypto.js

const forge = require('node-forge');

/**
 * Extrae datos del certificado de forma segura y robusta.
 * @param {string} cerBase64 - El contenido del archivo .cer en Base64.
 * @returns {object} Un objeto con datos del certificado listos para usar en la firma.
 */
function processCertificate(cerBase64) {
    // AÑADIMOS UN LOG PARA VERIFICAR QUE EL CÓDIGO NUEVO ESTÁ CORRIENDO
    console.log('[Crypto.js] Ejecutando la versión final y correcta de processCertificate...');

    const cerDer = forge.util.decode64(cerBase64);
    const cerAsn1 = forge.asn1.fromDer(cerDer);
    const certificate = forge.pki.certificateFromAsn1(cerAsn1);

    // --- LA FORMA CANÓNICA Y SEGURA DE OBTENER LOS DATOS DEL EMISOR ---
    // Usamos el método .toString() que la librería provee para esto.
    // Esto genera una cadena de Distinguished Name (DN) formateada correctamente.
    const issuerData = certificate.issuer.toString();
    // --- FIN DE LA CORRECCIÓN ---

    const certificatePem = forge.pki.certificateToPem(certificate);
    const pureCertBase64 = certificatePem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/\r/g, '')
        .replace(/\n/g, '');

    console.log(`[Crypto.js] IssuerData generado: ${issuerData}`); // LOG DE VERIFICACIÓN
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
