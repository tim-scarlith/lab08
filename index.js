const express = require('express');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { js2xml } = require('xml-js'); 
const cors = require('cors'); 


dotenv.config();


const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY_SECRETA = process.env.API_KEY_SECRETA;
const JWT_SECRETO = process.env.JWT_SECRETO;

app.use(express.json());
app.use(cors()); 

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
class AppError extends Error {
    constructor(code, message, status = 500, details = []) {
        super(message);
        this.name = 'AppError';
        this.code = code; 
        this.status = status; 
        this.details = details; 
    }
}
/**
 * Convierte un objeto o array JS a formato XML simple.
 * @param {Object|Array} data - Los datos a convertir.
 * @returns {string} La representación XML.
 */
const convertToXml = (data, rootTag = 'response') => {
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

    res.format({
        'application/json': () => {
            res.status(status).json(responseBody);
        },
        'application/xml': () => {
            
            const xml = convertToXml(responseBody, 'success');
            res.status(status).type('application/xml').send(xml);
        },
        'default': () => {
             
            res.status(status).json(responseBody);
        }
    });
};

const checkApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;

    if (!apiKey || apiKey !== API_KEY_SECRETA) {
        
        return next(new AppError('API_KEY_INVALIDA', 'API Key faltante o inválida.', 401));
    }
    next();
};

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
        const user = jwt.verify(token, JWT_SECRETO);
        req.user = user; 
        next();
    } catch (err) {
       
        return next(new AppError('JWT_INVALIDO', 'Token de autenticación JWT inválido o expirado.', 401));
    }
};

/**
 * Middleware para validar el rol del usuario (Autorización).
 * @param {Array<string>} allowedRoles - Roles permitidos (ej: ['admin', 'editor']).
 */
const checkRole = (allowedRoles) => (req, res, next) => {
    if (!req.user || !req.user.role) {
        
        return next(new AppError('NO_AUTENTICADO', 'Usuario no autenticado. Role faltante.', 401));
    }

    if (!allowedRoles.includes(req.user.role)) {
       
        return next(new AppError('PERMISO_DENEGADO', `Acceso denegado. Se requiere uno de los siguientes roles: ${allowedRoles.join(', ')}.`, 403));
    }
    next();
};
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

app.post('/auth/login', checkApiKey, (req, res, next) => {
    const { username, password } = req.body;

    
    if (!username || !password) {
        return next(new AppError('CREDENCIALES_FALTANTES', 'Username y password son requeridos.', 400));
    }
    const users = readJsonFile(USERS_DB_PATH);
    const user = users.find(u => u.username === username && u.password === password);

    if (!user) {
        return next(new AppError('CREDENCIALES_INVALIDAS', 'Credenciales de usuario inválidas.', 401));
    }

    // Generar el JWT
    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRETO,
        { expiresIn: '1h' } 
    );

    sendSuccessResponse(req, res, 200, { token, role: user.role });
});

app.get('/products', checkApiKey, (req, res, next) => {
    try {
        const products = readJsonFile(PRODUCTS_DB_PATH);
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


app.get('/products/:id', checkApiKey, (req, res, next) => {
    try {
        const productId = req.params.id;
        const products = readJsonFile(PRODUCTS_DB_PATH);
        const product = products.find(p => p.id === productId);

        if (!product) {
            
            return next(new AppError('PRODUCTO_NO_ENCONTRADO', `Producto con ID ${productId} no encontrado.`, 404));
        }

        sendSuccessResponse(req, res, 200, product);
    } catch (error) {
        next(error);
    }
});


app.post('/products', checkAuth, checkRole(['admin', 'editor']), (req, res, next) => {
    try {
        const newProduct = req.body;

        
        const validationErrors = validateProduct(newProduct);
        if (validationErrors.length > 0) {
            
            return next(new AppError('DATOS_INVALIDOS', 'Error de validación en los datos del producto.', 422, validationErrors));
        }

        let products = readJsonFile(PRODUCTS_DB_PATH);

        const isSkuDuplicate = products.some(p => p.sku === newProduct.sku);
        if (isSkuDuplicate) {
            
            return next(new AppError('SKU_DUPLICADO', `El SKU '${newProduct.sku}' ya existe.`, 409));
        }

        newProduct.id = uuidv4(); 
        
        
        products.push(newProduct);
        writeJsonFile(PRODUCTS_DB_PATH, products);

        
        sendSuccessResponse(req, res, 201, newProduct);

    } catch (error) {
        next(error);
    }
});


app.put('/products/:id', checkAuth, checkRole(['admin', 'editor']), (req, res, next) => {
    try {
        const productId = req.params.id;
        const updateData = req.body;

        
        const validationErrors = validateProduct(updateData);
        if (validationErrors.length > 0) {
            return next(new AppError('DATOS_INVALIDOS', 'Error de validación en los datos del producto.', 422, validationErrors));
        }

        let products = readJsonFile(PRODUCTS_DB_PATH);
        const productIndex = products.findIndex(p => p.id === productId);

        if (productIndex === -1) {
            
            return next(new AppError('PRODUCTO_NO_ENCONTRADO', `Producto con ID ${productId} no encontrado.`, 404));
        }
        
        
        const isSkuDuplicate = products.some((p, index) => p.sku === updateData.sku && index !== productIndex);
        if (isSkuDuplicate) {
            
            return next(new AppError('SKU_DUPLICADO', `El SKU '${updateData.sku}' ya existe en otro producto.`, 409));
        }

        
        products[productIndex] = { ...products[productIndex], ...updateData, id: productId }; 
        writeJsonFile(PRODUCTS_DB_PATH, products);

        
        sendSuccessResponse(req, res, 200, products[productIndex]);

    } catch (error) {
        next(error);
    }
});


app.delete('/products/:id', checkAuth, checkRole(['admin']), (req, res, next) => {
    try {
        const productId = req.params.id;
        let products = readJsonFile(PRODUCTS_DB_PATH);
        const initialLength = products.length;

        
        products = products.filter(p => p.id !== productId);

        if (products.length === initialLength) {
            
            return next(new AppError('PRODUCTO_NO_ENCONTRADO', `Producto con ID ${productId} no encontrado.`, 404));
        }

        
        writeJsonFile(PRODUCTS_DB_PATH, products);


        res.status(204).end();

    } catch (error) {
        next(error);
    }
});



app.use((err, req, res, next) => {
    
    let status = 500;
    let code = 'ERROR_INTERNO';
    let message = 'Un error inesperado ha ocurrido en el servidor.';
    let details = [];

    
    if (err instanceof AppError) {
        status = err.status;
        code = err.code;
        message = err.message;
        details = err.details;
    } else if (err.name === 'SyntaxError' && err.status === 400) {
        
        status = 400;
        code = 'JSON_MALFORMADO';
        message = 'El cuerpo de la solicitud (payload) contiene JSON mal formado.';
    } else {
        
        console.error('Error no controlado:', err.stack);
    }

    
    const errorResponse = {
        error: {
            code: code,
            message: message,
            details: details,
            timestamp: new Date().toISOString(),
            path: req.originalUrl,
        }
    };

    
    res.format({
        'application/json': () => {
            res.status(status).json(errorResponse);
        },
        'application/xml': () => {
            
            const xml = convertToXml(errorResponse, 'errorResponse');
            res.status(status).type('application/xml').send(xml);
        },
        'default': () => {
             
            res.status(status).json(errorResponse);
        }
    });
});


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
});