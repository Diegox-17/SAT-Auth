const express = require('express');
const { createAuthSignature } = require('../services/signature'); // Corregimos la importación
const { sendSoapRequest } = require('../services/soapClient');
const { parseStringPromise } = require('xml2js');

const router = express.Router();
const SAT_AUTH_URL = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc';
const SOAP_ACTION = 'http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica';

router.post('/', async (req, res) => {
    console.log('----------------------------------------------------');
    console.log('[AUTH] Petición recibida en /auth');

    const { cerBase64, keyPem, password } = req.body;

    if (!cerBase64 || !keyPem || !password) {
        console.error('[AUTH] Error: Faltan parámetros en la petición.');
        return res.status(400).json({ error: 'Faltan parámetros: cerBase64, keyPem, password son requeridos.' });
    }
    console.log('[AUTH] Parámetros recibidos correctamente.');

    try {
        // 1. Crear el sobre SOAP firmado
        console.log('[AUTH] PASO 1: Creando sobre SOAP firmado...');
        const signedXml = createAuthSignature(cerBase64, keyPem, password);
        console.log('[AUTH] PASO 1 completado. Longitud del XML:', signedXml.length);

        // 2. Enviar la petición al SAT
        console.log('[AUTH] PASO 2: Enviando petición SOAP al SAT...');
        const satResponseXml = await sendSoapRequest(SAT_AUTH_URL, SOAP_ACTION, signedXml);
        console.log('[AUTH] PASO 2 completado. Respuesta recibida del SAT.');

        // 3. Procesar la respuesta
        console.log('[AUTH] PASO 3: Procesando respuesta XML del SAT...');
        const parsedResponse = await parseStringPromise(satResponseXml, { explicitArray: false, tagNameProcessors: [str => str.split(':').pop()] });
        const token = parsedResponse.Envelope.Body.AutenticaResponse.AutenticaResult;

        if (!token) {
             console.error('[AUTH] Error: No se encontró el token en la respuesta del SAT.');
             throw new Error('No se pudo obtener el token de la respuesta del SAT.');
        }
        
        console.log('[AUTH] PASO 3 completado. Token obtenido exitosamente.');
        console.log('----------------------------------------------------');
        res.status(200).json({ token });

    } catch (error) {
        console.error('[AUTH] ERROR FATAL en el proceso de autenticación:', error.message);
        // Si axios lanzó un error, puede contener data del SAT que es muy útil
        const errorMessage = error.response ? error.response.data : error.message;
        console.error('[AUTH] Detalles del error:', errorMessage);
        console.log('----------------------------------------------------');
        res.status(500).json({ error: 'Error al comunicarse con el SAT.', details: errorMessage });
    }
});

module.exports = router;
