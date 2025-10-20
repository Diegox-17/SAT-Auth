# Microservicio de Integración con Web Services del SAT

Este microservicio encapsula la complejidad de la comunicación con los servicios de Autenticación y Descarga Masiva de CFDI del SAT.

## Arquitectura

- **Tecnología**: Node.js + Express
- **Contenerización**: Docker

## Endpoints

### 1. Autenticación

- **Ruta**: `POST /auth`
- **Propósito**: Obtiene un token de seguridad del SAT.
- **Body (JSON)**:
  ```json
  {
    "cerBase64": "String: Contenido del archivo .cer en Base64",
    "keyPem": "String: Contenido del archivo .key en formato PEM",
    "password": "String: Contraseña de la FIEL"
  }
  ```
- **Respuesta Exitosa (200 OK)**:
  ```json
  {
    "token": "El token de seguridad obtenido"
  }
  ```

---

_Más endpoints serán documentados aquí a medida que se implementen._

## Ejecución Local

1. Asegúrate de tener Docker y Docker Compose instalados.
2. Clona el repositorio.
3. Desde la raíz del proyecto, ejecuta:
   ```bash
   docker-compose up --build
   ```
4. El servicio estará disponible en `http://localhost:3000`.
