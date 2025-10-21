// src/routes/verificacion.js

const express = require('express');
const { signVerificationRequest } = require('../services/signature');
const { sendAuthenticatedRequest } = require('../services/soapClient');

const router = express.Router();

router.post('/', async (req, res) => {
    const { authToken, fiel, idSolicitud } = req.body;

    // --- VALIDACIÓN CORREGIDA Y ROBUSTA ---
    // 1. Validar que los objetos principales existen
    if (!authToken || !fiel || !idSolicitud) {
        return res.status(400).json({ 
            error: 'Faltan parámetros principales. Se requiere: authToken, fiel, idSolicitud.' 
        });
    }

    // 2. Validar que el objeto 'fiel' está completo
    if (!fiel.rfc || !fiel.cerBase64 || !fiel.keyPem || !fiel.password) {
        return res.status(400).json({ 
            error: 'El objeto "fiel" está incompleto. Se requiere: rfc, cerBase64, keyPem y password.' 
        });
    }
    // --- FIN DE LA VALIDACIÓN ---

    try {
        // Ahora es seguro usar fiel.rfc
        const rfcSolicitante = fiel.rfc;

        const signedXml = await signVerificationRequest(fiel, idSolicitud, rfcSolicitante);
        
        const soapResponse = await sendAuthenticatedRequest(
            process.env.SAT_VERIFY_URL,
            signedXml,
            'http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga',
            authToken
        );

        if (!soapResponse.success) {
            const statusCode = soapResponse.error?.statusCode || 500;
            return res.status(statusCode).json({ error: 'Error del servicio del SAT', details: soapResponse.error?.message });
        }
        
        const result = soapResponse.data.VerificaSolicitudDescargaResponse.VerificaSolicitudDescargaResult;
        
        const status = result.$;
        const packageIds = result.IdsPaquetes || null;

        const finalResponse = {
            CodEstatus: status.CodEstatus,
            EstadoSolicitud: status.EstadoSolicitud,
            CodigoEstadoSolicitud: status.CodigoEstadoSolicitud,
            NumeroCFDIs: status.NumeroCFDIs,
            Mensaje: status.Mensaje,
            Paquetes: Array.isArray(packageIds) ? packageIds : (packageIds ? [packageIds] : [])
        };

        res.status(200).json(finalResponse);

    } catch (error) {
        console.error('Error en el endpoint de verificación:', error.message);
        res.status(500).json({ error: 'Hubo un error al procesar la solicitud de verificación.', details: error.message });
    }
});

module.exports = router;
