// src/routes/descarga.js

const express = require('express');
const { generateDownloadSignature } = require('../services/signature');
const { sendAuthenticatedRequest } = require('../services/soapClient');

const router = express.Router();

const handleDownloadRequest = async (req, res, tipo) => {
    const { authToken, fiel, requestData } = req.body;

    // Validación básica
    if (!authToken || !fiel || !requestData) {
        return res.status(400).json({ error: 'Faltan parámetros: authToken, fiel, requestData son requeridos.' });
    }

    try {
        const signedXml = await generateDownloadSignature(fiel, requestData);

        console.log('--- XML FINAL A PUNTO DE SER ENVIADO AL SAT ---');
        console.log(signedXml);
        console.log('---------------------------------------------');
        
        const action = `http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga${tipo}`;
        console.log(`[Route] Enviando petición SOAP a ${process.env.SAT_DOWNLOAD_URL} con action: ${action}`);

        const soapResponse = await sendAuthenticatedRequest(
            process.env.SAT_DOWNLOAD_URL,
            signedXml,
            action,
            authToken
        );

        if (!soapResponse.success) {
            console.error('[Route] Error en la petición:', soapResponse.error);
            return res.status(soapResponse.error.statusCode || 500).json({ error: 'Error en la petición', details: soapResponse.error.message });
        }
        
        // --- CORRECCIÓN CLAVE: EXTRAER EL RESULTADO CORRECTO ---
        // Navegamos dentro del objeto 'Body' que nos devuelve el soapClient
        const responseKey = `SolicitaDescarga${tipo}Response`;
        const resultKey = `SolicitaDescarga${tipo}Result`;
        
        const result = soapResponse.data[responseKey][resultKey].$; // El '$' contiene los atributos que necesitamos

        console.log('[Route] Respuesta del SAT procesada con éxito:', result);

        // Devolvemos un JSON limpio y plano
        res.status(200).json(result);

    } catch (error) {
        console.error(`[Route] Error fatal en la ruta de descarga (${tipo}):`, error);
        res.status(500).json({ error: 'Error interno del servidor.', details: error.message });
    }
};

router.post('/recibidos', (req, res) => handleDownloadRequest(req, res, 'Recibidos'));
router.post('/emitidos', (req, res) => handleDownloadRequest(req, res, 'Emitidos'));

module.exports = router;


