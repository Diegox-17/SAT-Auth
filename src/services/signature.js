function createAuthSignature(cerBase64, keyPem, password) {
    // 1. Procesar certificados y llaves
    const { pureCertBase64 } = processCertificate(cerBase64);
    const privateKey = decryptPrivateKey(keyPem, password);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

    // 2. Generar Timestamps y UUIDs
    const now = new Date();
    const expires = new Date(now.getTime() + 5 * 60000); // 5 minutos de validez
    const createdString = now.toISOString().substring(0, 19) + 'Z';
    const expiresString = expires.toISOString().substring(0, 19) + 'Z';
    const timestampId = `_0`;
    const securityTokenId = `uuid-${uuidv4()}-1`;

    // 3. Construir el XML base (sin firmar)
    const xml = `
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <s:Header>
                <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <u:Timestamp u:Id="${timestampId}">
                        <u:Created>${createdString}</u:Created>
                        <u:Expires>${expiresString}</u:Expires>
                    </u:Timestamp>
                    <o:BinarySecurityToken u:Id="${securityTokenId}" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${pureCertBase64}</o:BinarySecurityToken>
                </o:Security>
            </s:Header>
            <s:Body>
                <Autentica xmlns="http://DescargaMasivaTerceros.gob.mx/"/>
            </s:Body>
        </s:Envelope>
    `;

    // 4. Firmar el XML
    // ****** INICIO DE LA CORRECCIÓN ******
    const sig = new SignedXml(null, {
      idAttribute: 'u:Id', // Le decimos a la librería cómo se llaman los atributos de ID
      implicitTransforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"]
    });
    // ****** FIN DE LA CORRECCIÓN ******

    sig.signingKey = privateKeyPem;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    
    // Le decimos que la referencia es a un URI que coincide con el ID del timestamp
    sig.addReference(
        `#${timestampId}`,
        ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );
    
    sig.keyInfoProvider = {
        getKeyInfo: () => {
            return `<o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#${securityTokenId}"/></o:SecurityTokenReference>`;
        }
    };

    sig.computeSignature(xml, {
        prefix: 'o',
        location: {
            reference: "//*[local-name()='Security']",
            action: 'append'
        }
    });

    return sig.getSignedXml();
}
