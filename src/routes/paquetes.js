// src/routes/paquetes.js

const express = require('express');
const { signPackageDownloadRequest } = require('../services/signature');
const { sendAuthenticatedRequest } = require('../services/soapClient');

const router = express.Router();

router.post('/', async (req, res) => {
    const { authToken, fiel, idPaquete } = req.body;

    if (!authToken || !fiel || !idPaquete || !fiel.rfc) {
        return res.status(400).json({ error: 'Parámetros requeridos: authToken, fiel (con rfc), idPaquete.' });
    }

    try {
        const signedXml = await signPackageDownloadRequest(fiel, idPaquete, fiel.rfc);

        const soapResponse = await sendAuthenticatedRequest(
            process.env.SAT_PACKAGE_DOWNLOAD_URL,
            signedXml,
            'http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar',
            authToken
        );

        if (!soapResponse.success) {
            return res.status(soapResponse.error.statusCode || 500).json({ error: 'Error del SAT al solicitar descarga', details: soapResponse.error.message });
        }

        // --- LÓGICA FINAL Y CORRECTA ---
        // 1. Extraemos el header y el body del sobre
        const header = soapResponse.data.Header;
        const body = soapResponse.data.Body;

        // 2. Revisamos el estado en el header
        const status = header.respuesta.$; // Los atributos están en el objeto '$'
        console.log('[Route Paquetes] Respuesta del Header del SAT:', status);

        if (status.CodEstatus !== '5000') {
            // Si el código no es 5000, es un error. Devolvemos el mensaje del header.
            return res.status(400).json({
                error: 'El SAT rechazó la descarga del paquete.',
                details: `Código: ${status.CodEstatus} - Mensaje: ${status.Mensaje}`
            });
        }
        
        // 3. Si el estado es 5000, procedemos a extraer el paquete del body
        const packageBase64 = body.RespuestaDescargaMasivaTercerosSalida.Paquete;
        if (!packageBase64) {
            return res.status(404).json({ error: 'El SAT reportó éxito (5000) pero no devolvió un paquete.' });
        }

        const packageBuffer = Buffer.from(packageBase64, 'base64');
        
        res.setHeader('Content-Disposition', `attachment; filename="${idPaquete}.zip"`);
        res.setHeader('Content-Type', 'application/zip');
        res.send(packageBuffer);

    } catch (error) {
        console.error(`[Route Paquetes] Error fatal al descargar el paquete ${idPaquete}:`, error);
        res.status(500).json({ error: 'Error interno del servidor.', details: error.message });
    }
});

module.exports = router;
