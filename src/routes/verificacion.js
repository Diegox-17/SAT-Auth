// src/routes/verificacion.js

const express = require('express');
const { signVerificationRequest } = require('../services/signature');
const { sendSoapRequest } = require('../services/soapClient');

const router = express.Router();

router.post('/', async (req, res) => {
    const { authToken, fiel, idSolicitud, rfcSolicitante } = req.body;

    if (!authToken || !fiel || !idSolicitud || !rfcSolicitante) {
        return res.status(400).json({ error: 'Faltan parámetros requeridos: authToken, fiel, idSolicitud, rfcSolicitante.' });
    }

    try {
        // 1. Generar el XML firmado para la verificación
        const signedXml = await signVerificationRequest(fiel, idSolicitud, rfcSolicitante);

        // 2. Enviar la petición SOAP al SAT
        const soapResponse = await sendSoapRequest(
            process.env.SAT_VERIFY_URL,
            signedXml,
            'http://DescargaMasivaTerceros.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga',
            authToken // El token se pasa aquí para ser incluido en el header
        );
        
        // 3. Procesar y devolver la respuesta del SAT
        // (Aquí se agregará la lógica de parsing de xml2js)
        res.status(200).json(soapResponse); // Por ahora devolvemos la respuesta cruda

    } catch (error) {
        console.error('Error en el endpoint de verificación:', error.message);
        res.status(500).json({ error: 'Hubo un error al procesar la solicitud de verificación.', details: error.message });
    }
});

module.exports = router;
