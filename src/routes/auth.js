const express = require('express');
const { createAuthSignature } = require('../services/signature');
const { sendSoapRequest } = require('../services/soapClient');
const { parseStringPromise } = require('xml2js');

const router = express.Router();
const SAT_AUTH_URL = process.env.SAT_AUTH_URL;
const SOAP_ACTION = 'http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica';

router.post('/', async (req, res) => {
    console.log('\n\n--- INICIO DE PETICIÓN DE AUTENTICACIÓN ---');
    console.log(`[AUTH] ${new Date().toISOString()} - Petición recibida en /auth`);

    const { cerBase64, keyPem, password } = req.body;

    if (!cerBase64 || !keyPem || !password) {
        console.error('[AUTH] ERROR: Faltan parámetros en el body de la petición.');
        console.log('--- FIN DE PETICIÓN CON ERROR ---');
        return res.status(400).json({ error: 'Faltan parámetros: cerBase64, keyPem, password son requeridos.' });
    }
    
    // Verificamos que los datos no estén vacíos y tengan un formato plausible
    console.log('[AUTH] Parámetros recibidos. Verificando contenido...');
    //console.log(`[AUTH]   - cerBase64 recibido (primeros 20 chars): ${cerBase64.substring(0, 20)}...`);
    //console.log(`[AUTH]   - keyPem recibido (primeros 20 chars): ${keyPem.substring(0, 20)}...`);
    //console.log(`[AUTH]   - password recibido: ${password ? 'Sí' : 'No'}`);

    try {
        console.log('[AUTH] PASO 1: Llamando a createAuthSignature...');
        const signedXml = createAuthSignature(cerBase64, keyPem, password);
        
        if (!signedXml) {
            throw new Error('createAuthSignature no devolvió ningún XML.');
        }

        //console.log('[AUTH] PASO 1 completado. XML Firmado generado.');
        // console.log('[AUTH] XML Firmado (para depuración):\n', signedXml); // Descomenta solo si es absolutamente necesario

        console.log('[AUTH] PASO 2: Enviando petición SOAP al SAT...');
        const satResponseXml = await sendSoapRequest(SAT_AUTH_URL, SOAP_ACTION, signedXml);
        //console.log('[AUTH] PASO 2 completado. Respuesta del SAT recibida.');

        console.log('[AUTH] PASO 3: Procesando respuesta del SAT...');
        const parsedResponse = await parseStringPromise(satResponseXml, { explicitArray: false, tagNameProcessors: [str => str.split(':').pop()] });
        const token = parsedResponse.Envelope.Body.AutenticaResponse.AutenticaResult;

        if (!token) {
             console.error('[AUTH] Error: No se encontró el token en la respuesta del SAT.');
             throw new Error('No se pudo obtener el token de la respuesta del SAT.');
        }
        
        console.log('[AUTH] ¡ÉXITO! Token obtenido.');
        console.log('--- FIN DE PETICIÓN EXITOSA ---');
        res.status(200).json({ token });

    } catch (error) {
        console.error('[AUTH] ERROR FATAL en el proceso de autenticación:', error.message);
        const errorMessage = error.response ? error.response.data : error.message;
        console.error('[AUTH] Detalles del error:', errorMessage);
        console.log('--- FIN DE PETICIÓN CON ERROR ---');
        res.status(500).json({ error: 'Error al comunicarse con el SAT.', details: errorMessage });
    }
});

module.exports = router;
