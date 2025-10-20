# Usamos una imagen oficial de Node.js ligera y segura
FROM node:18-alpine

# Creamos un directorio para la aplicación dentro del contenedor
WORKDIR /usr/src/app

# Copiamos los archivos de dependencias. Esto aprovecha el cache de Docker.
COPY package*.json ./

# Instalamos las dependencias
RUN npm install

# Copiamos el resto del código de la aplicación
COPY . .

# Exponemos el puerto en el que corre nuestra aplicación
EXPOSE 3000

# El comando para iniciar la aplicación cuando el contenedor arranque
CMD [ "node", "src/app.js" ]
