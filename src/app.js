const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const { SignedXml } = require("xml-crypto");

const app = express();
app.use(express.json({ limit: "5mb" })); // Acepta JSON en el body, con un límite generoso

const PORT = 3000;

// Endpoint principal para la autenticación
app.post("/autentica", async (req, res) => {
  try {
    // 1. Recibir los datos de la FIEL desde el body de la petición
    const { cerBase64, keyPem, password } = req.body;

    if (!cerBase64 || !keyPem || !password) {
      return res
        .status(400)
        .json({
          error:
            "Faltan datos de la FIEL: cerBase64, keyPem y password son requeridos.",
        });
    }

    // 2. Desencriptar la llave privada usando la contraseña
    // Esto reemplaza el comando 'openssl' que usabas en n8n
    let privateKeyBuffer;
    try {
      privateKeyBuffer = crypto.createPrivateKey({
        key: Buffer.from(keyPem, "utf8"),
        format: "pem",
        passphrase: password,
      });
    } catch (e) {
      console.error("Error al desencriptar la llave privada:", e.message);
      return res
        .status(400)
        .json({
          error: "Contraseña de la FIEL incorrecta o archivo .key corrupto.",
        });
    }

    // 3. Lógica de firma (nuestro código ya perfeccionado)
    const cleanCertificate = cerBase64
      .replace(
        /(\r\n|\n|\r|-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----)/gm,
        ""
      )
      .trim();
    const now = new Date();
    const created = now.toISOString().split(".")[0] + "Z";
    const expires =
      new Date(now.getTime() + 5 * 60000).toISOString().split(".")[0] + "Z";
    const timestampId = `_0`;
    const tokenId = `uuid-${crypto.randomUUID()}`;

    const soapRequestString = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><o:Security s:mustUnderstand="1"><u:Timestamp u:Id="${timestampId}"><u:Created>${created}</u:Created><u:Expires>${expires}</u:Expires></u:Timestamp><o:BinarySecurityToken u:Id="${tokenId}" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${cleanCertificate}</o:BinarySecurityToken></o:Security></s:Header><s:Body><des:Autentica/></s:Body></s:Envelope>`;

    const signer = new SignedXml();
    signer.signingKey = privateKeyBuffer; // Usamos la llave desencriptada
    signer.canonicalizationAlgorithm =
      "http://www.w3.org/2001/10/xml-exc-c14n#";
    signer.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    signer.keyInfoProvider = {
      getKeyInfo: () =>
        `<o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#${tokenId}"/></o:SecurityTokenReference>`,
    };
    const referenceOptions = {
      xpath: "//*[local-name(.)='Timestamp']",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    };
    signer.addReference(referenceOptions);
    signer.computeSignature(soapRequestString, {
      location: {
        reference: "//*[local-name(.)='Security']",
        action: "append",
      },
    });
    const finalSoapRequest = signer.getSignedXml();

    // 4. Petición al SAT
    const response = await axios.post(
      "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc",
      finalSoapRequest,
      {
        headers: {
          "Content-Type": "text/xml; charset=utf-8",
          SOAPAction:
            "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica",
        },
        validateStatus: () => true,
      }
    );

    if (response.status !== 200 || response.data.includes("<s:Fault>")) {
      console.error("Respuesta de error del SAT:", response.data);
      return res
        .status(502)
        .json({
          error: "El SAT rechazó la petición.",
          sat_status: response.status,
          sat_response: response.data,
        });
    }

    const tokenMatch = response.data.match(
      /<AutenticaResult>([^<]+)<\/AutenticacionResult>/
    );
    const token = tokenMatch ? tokenMatch[1] : null;

    if (!token) {
      return res
        .status(500)
        .json({
          error: "Respuesta exitosa del SAT pero no se encontró el token.",
        });
    }

    // 5. Devolver el token
    res.status(200).json({ token: token });
  } catch (error) {
    console.error("Error interno en el servicio:", error);
    res
      .status(500)
      .json({ error: "Error interno del servidor.", message: error.message });
  }
});

app.listen(PORT, () => {
  console.log(
    `Servicio de autenticación del SAT escuchando en el puerto ${PORT}`
  );
});
