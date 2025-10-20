const express = require('express');
const createAuthSignature = require('../services/signature').createAuthSignature;
const sendSoapRequest = require('../services/soapClient').sendSoapRequest;
const { parseStringPromise } = require('xml2js');

const router = express.Router();
const SAT_AUTH_URL = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc';
const SOAP_ACTION = 'http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica';

router.post('/', async (req, res) => {
    const { cerBase64, keyPem, password } = req.body;

    if (!cerBase64 || !keyPem || !password) {
        return res.status(400).json({ error: 'Faltan parámetros: cerBase64, keyPem, password son requeridos.' });
    }

    try {
        // 1. Crear el sobre SOAP firmado
        const signedXml = createAuthSignature(cerBase64, keyPem, password);
        
        // 2. Enviar la petición al SAT
        const satResponseXml = await sendSoapRequest(SAT_AUTH_URL, SOAP_ACTION, signedXml);
        
        // 3. Procesar la respuesta
        const parsedResponse = await parseStringPromise(satResponseXml, { explicitArray: false, tagNameProcessors: [str => str.split(':').pop()] });
        const token = parsedResponse.Envelope.Body.AutenticaResponse.AutenticaResult;

        if (!token) {
             throw new Error('No se pudo obtener el token de la respuesta del SAT.');
        }

        res.status(200).json({ token });

    } catch (error) {
        console.error('Error en el proceso de autenticación:', error.message);
        // Si axios lanzó un error, puede contener data del SAT
        const errorMessage = error.response ? error.response.data : error.message;
        res.status(500).json({ error: 'Error al comunicarse con el SAT.', details: errorMessage });
    }
});

module.exports = router;