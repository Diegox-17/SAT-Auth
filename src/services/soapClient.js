const axios = require('axios');

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

module.exports = { sendSoapRequest };