# Usamos una imagen oficial de Node.js
FROM node:18-alpine

# Creamos el directorio de trabajo
WORKDIR /usr/src/app

# Copiamos el package.json y package-lock.json
COPY package*.json ./

# Instalamos las dependencias
RUN npm install

# Copiamos el resto del código de la aplicación
COPY . .

# Exponemos el puerto que usará la aplicación
EXPOSE 3000

# El comando para iniciar la aplicación
CMD [ "npm", "start" ]