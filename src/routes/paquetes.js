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

        const soapAction = 'http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar';

        const soapResponse = await sendAuthenticatedRequest(
            process.env.SAT_PACKAGE_DOWNLOAD_URL,
            signedXml,
            soapAction,
            authToken
        );

        if (!soapResponse.success) {
            console.error('[Route Paquetes] El SAT devolvió un error:', soapResponse.error);
            return res.status(soapResponse.error.statusCode || 500).json({ 
                error: 'El SAT rechazó la descarga del paquete.', 
                details: soapResponse.error.message 
            });
        }
        
        // --- LÓGICA ROBUSTA PARA PROCESAR LA RESPUESTA ---
        // La respuesta de descarga, a diferencia de las otras, NO tiene la estructura anidada.
        // El paquete viene directamente en el Body.
        const packageBase64 = soapResponse.data.Paquete;

        if (!packageBase64) {
            // Esto puede pasar si el SAT devuelve una respuesta 200 OK pero sin el paquete.
            // Aunque es raro, es bueno manejarlo.
            return res.status(404).json({ error: 'El SAT no devolvió un paquete en la respuesta, aunque la petición fue exitosa.' });
        }

        const packageBuffer = Buffer.from(packageBase64, 'base64');
        
        res.setHeader('Content-Disposition', `attachment; filename="${idPaquete}.zip"`);
        res.setHeader('Content-Type', 'application/zip');
        res.send(packageBuffer);

    } catch (error) {
        // Ahora 'idPaquete' SÍ existe en este scope.
        console.error(`[Route Paquetes] Error fatal al procesar el paquete ${idPaquete}:`, error);
        res.status(500).json({ error: 'Error interno del servidor.', details: error.message });
    }
});

module.exports = router;
