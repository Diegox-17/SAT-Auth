// /src/routes/descarga.js
const express = require('express');
const router = express.Router();
const { generateDownloadSignature } = require('../services/signature');
// Importamos ambas funciones, pero usaremos la nueva
const { sendAuthenticatedRequest } = require('../services/soapClient');

// URL del servicio de descarga (es buena práctica tenerla como constante o variable de entorno)
// URL Aparentemente incorrecta const SAT_DOWNLOAD_URL = "https://descargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc";
// URL Aparentemente incorrecta const SAT_DOWNLOAD_URL = "https://descargamasivasolicitud.cloudapp.net/SolicitaDescargaService.svc";
const SAT_DOWNLOAD_URL = "https://cfdisolicitud.cloudapp.net/SolicitaDescargaService.svc";
// El namespace es el mismo para ambas operaciones
const SOAP_ACTION_BASE = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService";


// Función para manejar la respuesta y evitar código repetido
const handleResponse = (res, result) => {
    if (result.success) {
        console.log('[Route] Petición exitosa. Enviando respuesta al cliente.');
        res.status(200).json(result.data);
    } else {
        console.error('[Route] Error en la petición:', result.error);
        res.status(result.error.statusCode || 500).json({ message: result.error.message });
    }
};


router.post('/recibidos', async (req, res) => {
    console.log('\n--- [Route] Nueva petición a /descarga/recibidos ---');
    try {
        const { authToken, fiel, requestData } = req.body;
        console.log('[Route] Datos de la solicitud recibidos:', requestData);
        
        const signedXml = await generateDownloadSignature(fiel, requestData, 'Recibidos');
        
        const soapAction = `${SOAP_ACTION_BASE}/SolicitaDescargaRecibidos`;
        console.log(`[Route] Enviando petición SOAP a ${SAT_DOWNLOAD_URL} con action: ${soapAction}`);
        
        const result = await sendAuthenticatedRequest(SAT_DOWNLOAD_URL, signedXml, soapAction, authToken);
        
        handleResponse(res, result);

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


router.post('/emitidos', async (req, res) => {
    try {
        const { authToken, fiel, requestData } = req.body;
        console.log('[Route] Datos de la solicitud recibidos:', requestData);

        const signedXml = await generateDownloadSignature(fiel, requestData, 'Emitidos');

        const soapAction = `${SOAP_ACTION_BASE}/SolicitaDescargaEmitidos`;
        console.log(`[Route] Enviando petición SOAP a ${SAT_DOWNLOAD_URL} con action: ${soapAction}`);
        
        const result = await sendAuthenticatedRequest(SAT_DOWNLOAD_URL, signedXml, soapAction, authToken);

        handleResponse(res, result);

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

module.exports = router;




