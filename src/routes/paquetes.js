// src/routes/paquetes.js

const express = require('express');
const { signPackageDownloadRequest } = require('../services/signature');
const { sendAuthenticatedRequest } = require('../services/soapClient');

const router = express.Router();

// El endpoint será POST / ya que lo montaremos en /descarga/paquetes
router.post('/', async (req, res) => {
    const { authToken, fiel, idPaquete } = req.body;

    if (!authToken || !fiel || !idPaquete || !fiel.rfc) {
        return res.status(400).json({ error: 'Parámetros requeridos: authToken, fiel (con rfc), idPaquete.' });
    }

    try {
        // 1. Firmar la petición de descarga
        const signedXml = await signPackageDownloadRequest(fiel, idPaquete, fiel.rfc);

        // 2. Enviar la petición SOAP al SAT
        const soapResponse = await sendAuthenticatedRequest(
            process.env.SAT_PACKAGE_DOWNLOAD_URL,
            signedXml,
            'http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar',
            authToken
        );

        if (!soapResponse.success) {
            return res.status(soapResponse.error.statusCode || 500).json({ error: 'Error del SAT al solicitar descarga', details: soapResponse.error.message });
        }

        // 3. Extraer el paquete en Base64 de la respuesta
        const packageBase64 = soapResponse.data.RespuestaDescargaMasivaTercerosSalida.Paquete;
        if (!packageBase64) {
            return res.status(404).json({ error: 'El SAT no devolvió un paquete en su respuesta.' });
        }

        // 4. Convertir de Base64 a un buffer binario
        const packageBuffer = Buffer.from(packageBase64, 'base64');
        
        // 5. Enviar el archivo .zip al cliente (n8n)
        res.setHeader('Content-Disposition', `attachment; filename="${idPaquete}.zip"`);
        res.setHeader('Content-Type', 'application/zip');
        res.send(packageBuffer);

    } catch (error) {
        console.error(`[Route Paquetes] Error fatal al descargar el paquete ${idPaquete}:`, error);
        res.status(500).json({ error: 'Error interno del servidor.', details: error.message });
    }
});

module.exports = router;
