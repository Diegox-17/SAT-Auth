// src/utils/crypto.js

const forge = require('node-forge');

function processCertificate(cerBase64) {
    console.log('[Crypto.js] v3 FINAL: Ejecutando la versión definitiva de processCertificate.');

    const cerDer = forge.util.decode64(cerBase64);
    const cerAsn1 = forge.asn1.fromDer(cerDer);
    const certificate = forge.pki.certificateFromAsn1(cerAsn1);

    // --- MÉTODO MANUAL PERO SEGURO Y COMPROBADO ---
    // Este método construye la cadena de forma explícita, evitando 'undefined'.
    const issuerData = certificate.issuer.attributes.map(attr => {
        const name = attr.shortName || attr.name || `OID.${attr.type}`;
        return `${name}=${attr.value}`;
    }).join(', ');
    // --- FIN DE LA CORRECCIÓN ---

    const certificatePem = forge.pki.certificateToPem(certificate);
    const pureCertBase64 = certificatePem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/\r/g, '')
        .replace(/\n/g, '');

    console.log(`[Crypto.js] v3 FINAL: IssuerData generado: ${issuerData}`);
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
