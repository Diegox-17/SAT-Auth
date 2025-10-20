const forge = require('node-forge');

/**
 * Extrae el certificado público de la FIEL y lo decodifica.
 * @param {string} cerBase64 - El contenido del archivo .cer en Base64.
 * @returns {object} Un objeto que contiene el certificado parseado y su versión en Base64 puro.
 */
function processCertificate(cerBase64) {
    const cerDer = forge.util.decode64(cerBase64);
    const cerAsn1 = forge.asn1.fromDer(cerDer);
    const certificate = forge.pki.certificateFromAsn1(cerAsn1);

    // El SAT requiere el certificado sin los headers BEGIN/END
    const certificatePem = forge.pki.certificateToPem(certificate);
    const pureCertBase64 = certificatePem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/\r/g, '')
        .replace(/\n/g, '');

    return { certificate, pureCertBase64 };
}

/**
 * Desencripta la llave privada de la FIEL.
 * @param {string} keyPem - El contenido del archivo .key en formato PEM.
 * @param {string} password - La contraseña de la FIEL.
 * @returns {object} La llave privada desencriptada.
 */
function decryptPrivateKey(keyPem, password) {
    try {
        const privateKey = forge.pki.decryptRsaPrivateKey(keyPem, password);
        if (!privateKey) {
             throw new Error("La contraseña de la FIEL es incorrecta o el archivo .key está dañado.");
        }
        return privateKey;
    } catch (e) {
        // Forge puede lanzar un error genérico si la contraseña es incorrecta.
        throw new Error("La contraseña de la FIEL es incorrecta. Verifíquela.");
    }
}


module.exports = { processCertificate, decryptPrivateKey };