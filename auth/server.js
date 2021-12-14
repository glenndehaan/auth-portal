/**
 * Import base packages
 */
const express = require('express');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const app = express();

/**
 * Import own modules
 */
const authenticate = require('./modules/authenticate');

/**
 * Check if we are using the dev version
 */
const dev = process.env.NODE_ENV !== 'production';

/**
 * Setup logger
 */
const log = require('simple-node-logger').createSimpleLogger({
    timestampFormat: 'YYYY-MM-DD HH:mm:ss.SSS'
});

/**
 * Set log level from config
 */
log.setLevel(dev ? 'trace' : 'info');

/**
 * Define global variables
 */
const jwt_settings = {
    algorithm: 'HS512',
    secret: 'ehKf5rmcLWkfeuTaTdbyZXZmVQQUAXdMWZ9R5fcJrCsgqGkdLUHXyTaARzeH',
    expiresIn: '24h'
};
const app_title = process.env.APP_TITLE || 'Auth Portal';
const app_header = process.env.APP_HEADER || 'Welcome';
const logo = process.env.LOGO || '/images/logo.png';
const logo_url = process.env.LOGO_URL || 'https://glenndehaan.com';
const email_placeholder = process.env.EMAIL_PLACEHOLDER || 'user@example.com';
const users = process.env.USERS || 'user@example.com:$apr1$jI2jqzEg$MyNJQxhcZFNygXP79xT/p.\n';

/**
 * Define global functions
 */
const random = (min, max) => Math.floor(Math.random() * (max - min)) + min;

/**
 * Trust proxy
 */
app.enable('trust proxy');

/**
 * Set template engine
 */
app.set('view engine', 'ejs');
app.set('views', `${__dirname}/template`);

/**
 * Enable cookie parser support
 */
app.use(cookieParser());

/**
 * Enable multer
 */
app.use(multer().none());

/**
 * Request logger
 */
app.use((req, res, next) => {
    log.trace(`[Web][REQUEST]: ${req.originalUrl}`);
    next();
});

/**
 * Serve static public dir
 */
app.use(express.static(`${__dirname}/public`));

/**
 * Configure routers
 */
app.get('/validate', (req, res) => {
    if(req.cookies && req.cookies.__auth_portal) {
        try {
            const check = jwt.verify(req.cookies.__auth_portal, jwt_settings.secret);
            if(check) {
                res.set('X-Auth-Portal-JWT', req.cookies.__auth_portal).set('X-Auth-Portal-Error', '').set('X-Auth-Portal-User', check.email).status(200).send();
            } else {
                res.set('X-Auth-Portal-JWT', req.cookies.__auth_portal).set('X-Auth-Portal-Error', 'Invalid or expired login!').set('X-Auth-Portal-User', '').status(401).send();
            }

            return;
        } catch (e) {
            res.set('X-Auth-Portal-JWT', req.cookies.__auth_portal).set('X-Auth-Portal-Error', 'Invalid or expired login!').set('X-Auth-Portal-User', '').status(401).send();
            return;
        }
    }

    res.set('X-Auth-Portal-JWT', '').set('X-Auth-Portal-Error', '').set('X-Auth-Portal-User', '').status(401).send();
});
app.get('/login', (req, res) => {
    res.render('index', {
        error: typeof req.query.error === 'string' && req.query.error !== '',
        error_text: req.query.error || '',
        redirect: req.query.url,
        image: `bg-${random(1, 6)}.jpg`,
        app_title,
        app_header,
        logo,
        logo_url,
        email_placeholder
    });
});
app.post('/login', async (req, res) => {
    const check = await authenticate(req.body.email, req.body.password, users);

    if(!check) {
        res.redirect(encodeURI(`/login?url=${req.body.redirect}&error=Invalid email/password!`));
        return;
    }

    res.cookie('__auth_portal', jwt.sign({email: req.body.email}, jwt_settings.secret, {
        algorithm: jwt_settings.algorithm,
        expiresIn: jwt_settings.expiresIn
    })).redirect(req.body.redirect);
});

/**
 * Setup default 404 message
 */
app.use((req, res) => {
    res.status(404);
    res.send('Not Found!')
});

/**
 * Disable powered by header for security reasons
 */
app.disable('x-powered-by');

/**
 * Start listening on port
 */
app.listen(3000, '0.0.0.0', () => {
    log.info(`App is running on: 0.0.0.0:3000`);
});
