const axios = require('axios');
const { parseStringPromise } = require('xml2js');

async function sendSoapRequest(url, action, xml) {
    try {
        const response = await axios.post(url, xml, {
            headers: {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': action,
            },
        });
        return response.data;
    } catch (error) {
        console.error(`Error en la petición SOAP a ${url}:`);
        // Imprimimos el error que devuelve el SAT para facilitar la depuración
        if (error.response) {
            console.error('Status:', error.response.status);
            console.error('Headers:', error.response.headers);
            console.error('Data:', error.response.data);
        } else {
            console.error('Error Message:', error.message);
        }
        // Re-lanzamos el error para que el manejador de la ruta lo capture
        throw error;
    }
}

// NUEVA FUNCIÓN para peticiones que requieren el token
async function sendAuthenticatedRequest(url, xml, soapAction, authToken) {
    if (!authToken) {
        // Devolvemos un error estructurado si no hay token
        return { 
            success: false, 
            error: { 
                statusCode: 401, 
                message: 'Se requiere un token de autenticación para esta operación.' 
            }
        };
    }
    
    try {
        const headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': soapAction,
            'Authorization': `WRAP access_token="${authToken}"` // Header de autorización
        };

        const { data } = await axios.post(url, xml, { headers });

        const parsedData = await parseStringPromise(data, {
            explicitArray: false,
            tagNameProcessors: [tag => tag.replace('s:', '').replace(/s:|des:|h:/, '')]
        });

        //console.log('[SOAP Client] Respuesta COMPLETA del SAT (parseada a JSON):');
        //console.log(JSON.stringify(parsedData, null, 2));

       
        if (!parsedData.Envelope || !parsedData.Envelope.Body) {
            // Si no tiene la estructura, es una respuesta inesperada (probablemente un Fault)
            console.error('[SOAP Client] Respuesta inesperada del SAT:', JSON.stringify(parsedData, null, 2));
            const faultMessage = parsedData.Fault?.faultstring || 'La respuesta del SAT no es un sobre SOAP válido.';
            return { success: false, error: { statusCode: 500, message: faultMessage }};
        }
        // --- FIN DE LA CORRECCIÓN ---
        
        const body = parsedData.Envelope.Body;
        
        console.log('[SOAP Client] Cuerpo de la respuesta del SAT (parseado):', JSON.stringify(body, null, 2));

        return { success: true, data: body };

    } 
    
    catch (error) {
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

module.exports = { sendSoapRequest,sendAuthenticatedRequest };
