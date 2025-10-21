// /src/services/soapClient.js

const axios = require('axios');
// --- CORRECCIÓN ---
// La siguiente línea importa la función que faltaba para procesar las respuestas XML.
const { parseStringPromise } = require('xml2js');

// Función original para la autenticación (sin token)
async function sendSoapRequest(url, xml, soapAction) {
    try {
        const headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': soapAction,
        };
        const { data } = await axios.post(url, xml, { headers });
        // Lógica de parseo para la respuesta de autenticación
        const parsedData = await parseStringPromise(data, {
             explicitArray: false,
             tagNameProcessors: [tag => tag.replace('s:', '').replace('o:', '')]
        });
        const token = parsedData.Envelope.Body.Security.Timestamp.Created; // Ajusta esta ruta si es necesario
        return { success: true, data: { token } };
    } catch (error) {
        console.error(`Error en la petición SOAP a ${url}:`);
        const errorMessage = error.response ? error.response.data : error.message;
        console.error('Error Message:', errorMessage);
        return { success: false, error: { statusCode: 500, message: errorMessage } };
    }
}

// Función para peticiones de descarga (CON token)
async function sendAuthenticatedRequest(url, xml, soapAction, authToken) {
    try {
        const headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': soapAction,
            'Authorization': `WRAP access_token="${authToken}"`
        };
        const { data } = await axios.post(url, xml, { headers });
        
        // Lógica de parseo para la respuesta de descarga
        const parsedData = await parseStringPromise(data, {
            explicitArray: false,
            // Elimina los prefijos 's:' y 'des:' para un acceso más fácil
            tagNameProcessors: [tag => tag.replace(/s:|des:/g, '')]
        });

        // Extraer el resultado directamente de la respuesta del SAT
        const result = parsedData.Envelope.Body.SolicitaDescargaResponse.SolicitaDescargaResult.$;

        return { success: true, data: result };

    } catch (error) {
        console.error('SOAP Client Authenticated Error:', error.response ? error.response.data : error.message);
        return { 
            success: false, 
            error: { 
                statusCode: error.response ? error.response.status : 500,
                message: error.response ? error.response.data : 'Error en la comunicación con el servicio del SAT.'
            }
        };
    }
}

module.exports = { 
    sendSoapRequest,
    sendAuthenticatedRequest
};
