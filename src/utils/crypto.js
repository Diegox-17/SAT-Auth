// src/utils/crypto.js

const forge = require('node-forge');

/**
 * Extrae datos del certificado, incluyendo el nombre del emisor en el formato requerido por el SAT.
 * @param {string} cerBase64 - El contenido del archivo .cer en Base64.
 * @returns {object} Un objeto con el certificado, el Base64 puro y los datos del emisor.
 */
function processCertificate(cerBase64) {
    const cerDer = forge.util.decode64(cerBase64);
    const cerAsn1 = forge.asn1.fromDer(cerDer);
    const certificate = forge.pki.certificateFromAsn1(cerAsn1);

    // --- LÓGICA AÑADIDA PARA GENERAR ISSUERDATA ---
    const issuerAttributes = certificate.issuer.attributes;
    const issuerData = issuerAttributes.map(attr => {
        const shortName = forge.pki.oids[attr.type] || 'OID.' + attr.type;
        // Se debe decodificar el valor del atributo para obtener el string
        const value = attr.value;
        return `${shortName}=${value}`;
    }).reverse().join(', '); // El orden inverso suele ser el esperado por el SAT
    // --- FIN DE LA LÓGICA AÑADIDA ---

    const certificatePem = forge.pki.certificateToPem(certificate);
    const pureCertBase64 = certificatePem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/\r/g, '')
        .replace(/\n/g, '');

    // Devolvemos el nuevo dato junto con los existentes
    return { certificate, issuerData, pureCertBase64 };
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
        throw new Error("La contraseña de la FIEL es incorrecta. Verifíquela.");
    }
}

module.exports = { processCertificate, decryptPrivateKey };
