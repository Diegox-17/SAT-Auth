// /src/routes/download.js

const express = require('express');
const router = express.Router();
const { generateDownloadSignature } = require('../services/signature'); // Crearemos esta función
const soapClient = require('../services/soapClient');

// Helper para manejar las respuestas
const handleResponse = (res, result) => {
    if (result.success) {
        res.status(200).json(result.data);
    } else {
        res.status(result.error.statusCode || 500).json({ message: result.error.message });
    }
};

/**
 * @route   POST /download/received
 * @desc    Solicita la descarga de CFDI Recibidos
 */
router.post('/received', async (req, res) => {
    try {
        const { authToken, fiel, requestData } = req.body;
        // 1. Generar la firma específica para la solicitud de recibidos
        const signedXml = await generateDownloadSignature(fiel, requestData, 'received');

        // 2. Enviar la petición SOAP al SAT
        const soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos";
        const result = await soapClient.sendRequest(process.env.SAT_DOWNLOAD_URL, signedXml, soapAction, authToken);
        
        handleResponse(res, result);

    } catch (error) {
        console.error('Error en /download/received:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

/**
 * @route   POST /download/issued
 * @desc    Solicita la descarga de CFDI Emitidos
 */
router.post('/issued', async (req, res) => {
    try {
        const { authToken, fiel, requestData } = req.body;
        // 1. Generar la firma específica para la solicitud de emitidos
        const signedXml = await generateDownloadSignature(fiel, requestData, 'issued');

        // 2. Enviar la petición SOAP al SAT
        const soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos";
        const result = await soapClient.sendRequest(process.env.SAT_DOWNLOAD_URL, signedXml, soapAction, authToken);

        handleResponse(res, result);

    } catch (error) {
        console.error('Error en /download/issued:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

module.exports = router;
