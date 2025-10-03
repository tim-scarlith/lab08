// Archivo principal de la API REST - Laboratorio 9 (IC8057)

// 1. Importaciones necesarias
const express = require('express');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { js2xml } = require('xml-js'); // Usado para la negociación de contenido (XML)

// Cargar variables de entorno del archivo .env
dotenv.config();

// 2. Configuración de la aplicación
const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY_SECRETA = process.env.API_KEY_SECRETA;
const JWT_SECRETO = process.env.JWT_SECRETO;

// Middleware para parsear JSON en el cuerpo de las peticiones
app.use(express.json());

// 3. Constantes y Utilidades de Persistencia (JSON)

// Rutas a los archivos de "base de datos"
const USERS_DB_PATH = path.join(__dirname, 'db', 'users.json');
const PRODUCTS_DB_PATH = path.join(__dirname, 'db', 'products.json');

/**
 * Lee y parsea un archivo JSON.
 * @param {string} filePath - Ruta al archivo JSON.
 * @returns {Array<Object>} El contenido del archivo como array de objetos.
 */
const readJsonFile = (filePath) => {
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error(`Error leyendo el archivo ${filePath}:`, error.message);
        // Si el archivo no existe o está vacío, retorna un array vacío
        return [];
    }
};

/**
 * Escribe datos en un archivo JSON.
 * @param {string} filePath - Ruta al archivo JSON.
 * @param {Array<Object>} data - Datos a escribir.
 */
const writeJsonFile = (filePath, data) => {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
        console.error(`Error escribiendo el archivo ${filePath}:`, error.message);
        throw new AppError('ERROR_PERSISTENCIA', 'Error al guardar los datos en el archivo JSON', 500);
    }
};

// 4. Clases de Errores Personalizados

/**
 * Clase para manejar errores controlados de la aplicación.
 */
class AppError extends Error {
    constructor(code, message, status = 500, details = []) {
        super(message);
        this.name = 'AppError';
        this.code = code; // Código de error (ej: NOT_FOUND, VALIDATION_ERROR)
        this.status = status; // Código de estado HTTP (ej: 404, 422)
        this.details = details; // Detalles adicionales de la validación
    }
}

// 5. Utilidades de Respuesta y Negociación de Contenido

/**
 * Convierte un objeto o array JS a formato XML simple.
 * @param {Object|Array} data - Los datos a convertir.
 * @returns {string} La representación XML.
 */
const convertToXml = (data, rootTag = 'response') => {
    // La opción compact: true simplifica la estructura de los nodos.
    return js2xml({ [rootTag]: data }, { compact: true, spaces: 4, fullTagEmptyElement: true });
};

/**
 * Envía una respuesta exitosa con el formato estandarizado (JSON o XML).
 * @param {express.Response} res - Objeto de respuesta de Express.
 * @param {number} status - Código de estado HTTP (ej: 200, 201, 204).
 * @param {Object|Array} data - Los datos a enviar.
 */
const sendSuccessResponse = (req, res, status, data) => {
    const responseBody = {
        data: data,
        metadata: {
            timestamp: new Date().toISOString(),
            path: req.originalUrl,
        }
    };

    // Negociación de contenido: soporta application/json y application/xml
    res.format({
        'application/json': () => {
            res.status(status).json(responseBody);
        },
        'application/xml': () => {
            // El rootTag se nombra 'success' para las respuestas exitosas
            const xml = convertToXml(responseBody, 'success');
            res.status(status).type('application/xml').send(xml);
        },
        'default': () => {
             // Por defecto, se usa JSON
            res.status(status).json(responseBody);
        }
    });
};

// 6. Middlewares de Seguridad

/**
 * Middleware para validar la API Key.
 * Protege las rutas públicas (auth y products GET).
 */
const checkApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;

    if (!apiKey || apiKey !== API_KEY_SECRETA) {
        // 401 Unauthorized: Credenciales faltantes o inválidas
        return next(new AppError('API_KEY_INVALIDA', 'API Key faltante o inválida.', 401));
    }
    next();
};

/**
 * Middleware para validar el JWT (Autenticación).
 * Protege las rutas de creación, actualización y eliminación.
 */
const checkAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return next(new AppError('JWT_FALTANTE', 'Token de autenticación JWT es requerido.', 401));
    }

    const [scheme, token] = authHeader.split(' ');
    if (scheme !== 'Bearer' || !token) {
        return next(new AppError('JWT_MALFORMADO', 'Formato del token JWT inválido. Use "Bearer [token]".', 401));
    }

    try {
        // Verificar y decodificar el token
        const user = jwt.verify(token, JWT_SECRETO);
        req.user = user; // Adjuntar datos del usuario a la solicitud
        next();
    } catch (err) {
        // 401 Unauthorized: Token inválido
        return next(new AppError('JWT_INVALIDO', 'Token de autenticación JWT inválido o expirado.', 401));
    }
};

/**
 * Middleware para validar el rol del usuario (Autorización).
 * @param {Array<string>} allowedRoles - Roles permitidos (ej: ['admin', 'editor']).
 */
const checkRole = (allowedRoles) => (req, res, next) => {
    if (!req.user || !req.user.role) {
        // Esto no debería suceder si checkAuth se ejecuta primero, pero es un buen control
        return next(new AppError('NO_AUTENTICADO', 'Usuario no autenticado. Role faltante.', 401));
    }

    if (!allowedRoles.includes(req.user.role)) {
        // 403 Forbidden: El usuario no tiene el rol necesario
        return next(new AppError('PERMISO_DENEGADO', `Acceso denegado. Se requiere uno de los siguientes roles: ${allowedRoles.join(', ')}.`, 403));
    }
    next();
};

// 7. Validaciones de Datos

/**
 * Valida los campos requeridos para un producto (Crear/Actualizar).
 * @param {Object} productData - Datos del producto.
 * @returns {Array<string>} Lista de errores de validación.
 */
const validateProduct = (productData) => {
    const errors = [];
    const { name, sku, price, stock, category } = productData;

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        errors.push("El campo 'name' es requerido y debe ser un texto.");
    }
    if (!sku || typeof sku !== 'string' || sku.trim().length === 0) {
        errors.push("El campo 'sku' es requerido y debe ser un texto.");
    }
    if (typeof price !== 'number' || price <= 0) {
        errors.push("El campo 'price' es requerido y debe ser un número positivo.");
    }
    if (typeof stock !== 'number' || stock < 0) {
        errors.push("El campo 'stock' es requerido y debe ser un número no negativo.");
    }
    if (!category || typeof category !== 'string' || category.trim().length === 0) {
        errors.push("El campo 'category' es requerido y debe ser un texto.");
    }

    return errors;
};

// 8. Controladores de Rutas

// --- AUTH ROUTE ---
app.post('/auth/login', checkApiKey, (req, res, next) => {
    const { username, password } = req.body;

    // Validación básica de credenciales
    if (!username || !password) {
        return next(new AppError('CREDENCIALES_FALTANTES', 'Username y password son requeridos.', 400));
    }

    // Buscar el usuario en el archivo JSON
    const users = readJsonFile(USERS_DB_PATH);
    const user = users.find(u => u.username === username && u.password === password);

    if (!user) {
        return next(new AppError('CREDENCIALES_INVALIDAS', 'Credenciales de usuario inválidas.', 401));
    }

    // Generar el JWT
    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRETO,
        { expiresIn: '1h' } // Token expira en 1 hora
    );

    sendSuccessResponse(req, res, 200, { token, role: user.role });
});

// --- PRODUCT ROUTES ---

// GET /products: Listado y paginación
app.get('/products', checkApiKey, (req, res, next) => {
    try {
        const products = readJsonFile(PRODUCTS_DB_PATH);
        
        // Manejo de Paginación
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const startIndex = (page - 1) * limit;
        const endIndex = page * limit;

        const paginatedProducts = products.slice(startIndex, endIndex);
        const totalProducts = products.length;
        const totalPages = Math.ceil(totalProducts / limit);

        const responseData = {
            pagination: {
                totalItems: totalProducts,
                totalPages: totalPages,
                currentPage: page,
                limit: limit,
            },
            products: paginatedProducts,
        };

        sendSuccessResponse(req, res, 200, responseData);
    } catch (error) {
        next(error);
    }
});

// GET /products/:id: Detalle de producto
app.get('/products/:id', checkApiKey, (req, res, next) => {
    try {
        const productId = req.params.id;
        const products = readJsonFile(PRODUCTS_DB_PATH);
        const product = products.find(p => p.id === productId);

        if (!product) {
            // 404 Not Found
            return next(new AppError('PRODUCTO_NO_ENCONTRADO', `Producto con ID ${productId} no encontrado.`, 404));
        }

        sendSuccessResponse(req, res, 200, product);
    } catch (error) {
        next(error);
    }
});

// POST /products: Crea un producto (requiere editor o admin)
app.post('/products', checkAuth, checkRole(['admin', 'editor']), (req, res, next) => {
    try {
        const newProduct = req.body;

        // 1. Validación de campos
        const validationErrors = validateProduct(newProduct);
        if (validationErrors.length > 0) {
            // 422 Unprocessable Content
            return next(new AppError('DATOS_INVALIDOS', 'Error de validación en los datos del producto.', 422, validationErrors));
        }

        let products = readJsonFile(PRODUCTS_DB_PATH);

        // 2. Control de duplicados (SKU único)
        const isSkuDuplicate = products.some(p => p.sku === newProduct.sku);
        if (isSkuDuplicate) {
            // 409 Conflict
            return next(new AppError('SKU_DUPLICADO', `El SKU '${newProduct.sku}' ya existe.`, 409));
        }

        // Asignar ID único
        newProduct.id = uuidv4(); 
        
        // 3. Persistencia
        products.push(newProduct);
        writeJsonFile(PRODUCTS_DB_PATH, products);

        // 4. Respuesta (201 Created)
        sendSuccessResponse(req, res, 201, newProduct);

    } catch (error) {
        next(error);
    }
});

// PUT /products/:id: Actualiza un producto (requiere editor o admin)
app.put('/products/:id', checkAuth, checkRole(['admin', 'editor']), (req, res, next) => {
    try {
        const productId = req.params.id;
        const updateData = req.body;

        // 1. Validación de campos (reutilizando la función)
        const validationErrors = validateProduct(updateData);
        if (validationErrors.length > 0) {
            return next(new AppError('DATOS_INVALIDOS', 'Error de validación en los datos del producto.', 422, validationErrors));
        }

        let products = readJsonFile(PRODUCTS_DB_PATH);
        const productIndex = products.findIndex(p => p.id === productId);

        if (productIndex === -1) {
            // 404 Not Found
            return next(new AppError('PRODUCTO_NO_ENCONTRADO', `Producto con ID ${productId} no encontrado.`, 404));
        }
        
        // 2. Control de duplicados (SKU único, excluyendo el producto actual)
        const isSkuDuplicate = products.some((p, index) => p.sku === updateData.sku && index !== productIndex);
        if (isSkuDuplicate) {
            // 409 Conflict
            return next(new AppError('SKU_DUPLICADO', `El SKU '${updateData.sku}' ya existe en otro producto.`, 409));
        }

        // 3. Actualización y Persistencia
        products[productIndex] = { ...products[productIndex], ...updateData, id: productId }; // Asegurar que el ID no cambie
        writeJsonFile(PRODUCTS_DB_PATH, products);

        // 4. Respuesta (200 OK)
        sendSuccessResponse(req, res, 200, products[productIndex]);

    } catch (error) {
        next(error);
    }
});

// DELETE /products/:id: Elimina un producto (requiere admin)
app.delete('/products/:id', checkAuth, checkRole(['admin']), (req, res, next) => {
    try {
        const productId = req.params.id;
        let products = readJsonFile(PRODUCTS_DB_PATH);
        const initialLength = products.length;

        // Filtrar y eliminar el producto
        products = products.filter(p => p.id !== productId);

        if (products.length === initialLength) {
            // No se encontró el producto para eliminar
            return next(new AppError('PRODUCTO_NO_ENCONTRADO', `Producto con ID ${productId} no encontrado.`, 404));
        }

        // 2. Persistencia
        writeJsonFile(PRODUCTS_DB_PATH, products);

        // 3. Respuesta (204 No Content)
        // Para 204, no se envía cuerpo, pero para mantener la coherencia
        // con el estándar de errores, podríamos usar 200 con un mensaje,
        // o simplemente 204. El estándar REST dicta 204.
        res.status(204).end();

    } catch (error) {
        next(error);
    }
});


// 9. Middleware Central de Manejo de Errores

/**
 * Middleware final para manejar todos los errores.
 */
app.use((err, req, res, next) => {
    // Determinar el código y mensaje de error
    let status = 500;
    let code = 'ERROR_INTERNO';
    let message = 'Un error inesperado ha ocurrido en el servidor.';
    let details = [];

    // Si es un AppError controlado (nuestros errores personalizados)
    if (err instanceof AppError) {
        status = err.status;
        code = err.code;
        message = err.message;
        details = err.details;
    } else if (err.name === 'SyntaxError' && err.status === 400) {
        // Manejo de error de sintaxis JSON
        status = 400;
        code = 'JSON_MALFORMADO';
        message = 'El cuerpo de la solicitud (payload) contiene JSON mal formado.';
    } else {
        // Log del error no controlado para debugging
        console.error('Error no controlado:', err.stack);
    }

    // Estructura de respuesta de error estandarizada
    const errorResponse = {
        error: {
            code: code,
            message: message,
            details: details,
            timestamp: new Date().toISOString(),
            path: req.originalUrl,
        }
    };

    // Negociación de contenido para errores
    res.format({
        'application/json': () => {
            res.status(status).json(errorResponse);
        },
        'application/xml': () => {
            // El rootTag se nombra 'errorResponse' para la respuesta de error
            const xml = convertToXml(errorResponse, 'errorResponse');
            res.status(status).type('application/xml').send(xml);
        },
        'default': () => {
             // Por defecto, se usa JSON
            res.status(status).json(errorResponse);
        }
    });
});


// 10. Iniciar el Servidor

app.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`API REST del Laboratorio 9 corriendo en http://localhost:${PORT}`);
    console.log(`Persistencia: Archivos JSON en la carpeta /db`);
    console.log(`======================================================\n`);
    console.log(`Rutas disponibles:`);
    console.log(`POST /auth/login (API Key)`);
    console.log(`GET /products (API Key, Paginación, Content Negotiation JSON/XML)`);
    console.log(`GET /products/:id (API Key, Content Negotiation JSON/XML)`);
    console.log(`POST /products (JWT: admin/editor)`);
    console.log(`PUT /products/:id (JWT: admin/editor)`);
    console.log(`DELETE /products/:id (JWT: admin)`);
    console.log(`\nUse 'admin' o 'editor' con password 'password123' para login.`);
    console.log(`No olvide configurar el archivo .env!`);
});
