// cors-config.js - NOVO ARQUIVO
const cors = require('cors');

class CORSConfig {
    constructor() {
        this.allowedOrigins = [
            'https://linkmagico-comercial.onrender.com',
            'https://seusite.com',
            'http://localhost:3000',
            'http://localhost:8080'
        ];

        this.corsOptions = {
            origin: (origin, callback) => {
                if (!origin) return callback(null, true);

                if (this.allowedOrigins.indexOf(origin) !== -1) {
                    callback(null, true);
                } else {
                    console.log(`Tentativa de acesso CORS bloqueada: ${origin}`);
                    callback(new Error('Nao permitido por CORS'), false);
                }
            },
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: [
                'Content-Type',
                'Authorization', 
                'X-CSRF-Token',
                'X-Requested-With',
                'Accept'
            ],
            exposedHeaders: [
                'X-CSRF-Token',
                'X-RateLimit-Limit',
                'X-RateLimit-Remaining'
            ],
            maxAge: 86400,
            preflightContinue: false,
            optionsSuccessStatus: 204
        };
    }

    getMiddleware() {
        return cors(this.corsOptions);
    }

    corsLogger(req, res, next) {
        const origin = req.get('Origin');
        if (origin && !this.allowedOrigins.includes(origin)) {
            console.log(`Tentativa de acesso CORS de origem nao autorizada: ${origin}`);
        }
        next();
    }

    addOrigin(origin) {
        if (!this.allowedOrigins.includes(origin)) {
            this.allowedOrigins.push(origin);
            console.log(`Origem adicionada ao CORS: ${origin}`);
        }
    }

    removeOrigin(origin) {
        const index = this.allowedOrigins.indexOf(origin);
        if (index > -1) {
            this.allowedOrigins.splice(index, 1);
            console.log(`Origem removida do CORS: ${origin}`);
        }
    }
}

module.exports = CORSConfig;