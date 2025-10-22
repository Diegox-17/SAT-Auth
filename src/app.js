const express = require('express');
const authRouter = require('./routes/auth');
const descargaRouter = require('./routes/descarga'); // Descarga
const verificacionRoutes = require('./routes/verificacion');
const paquetesRoutes = require('./routes/paquetes');

const app = express();
const port = 3000;

// Middlewares
app.use(express.json({ limit: '10mb' })); // Aumentamos el límite para los Base64
app.use(express.static('public')); // Para servir nuestra API-LAB

// Rutas
app.use('/auth', authRouter);
app.use('/descarga', descargaRouter); // Descarga
app.use('/descarga/verificar', verificacionRoutes);
app.use('/descarga/paquetes', paquetesRoutes);
app.listen(port, () => {
    console.log(`Servicio SAT escuchando en http://localhost:${port}`);
});
