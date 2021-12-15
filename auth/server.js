/**
 * Import base packages
 */
const express = require('express');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const atob = require('atob');
const btoa = require('btoa');
const google = require('googleapis').google;
const app = express();

/**
 * Define Google OAuth Client
 */
const GOAuth2 = google.auth.OAuth2;

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
const logo = process.env.LOGO || '/images/logo_edit.png';
const logo_url = process.env.LOGO_URL || 'https://glenndehaan.com';
const info_banner = process.env.INFO_BANNER || '';
const email_placeholder = process.env.EMAIL_PLACEHOLDER || 'user@example.com';
const users = process.env.USERS || 'user@example.com:$apr1$jI2jqzEg$MyNJQxhcZFNygXP79xT/p.\n';
const provider_google = process.env.PROVIDER_GOOGLE || false;
const provider_google_client_id = process.env.PROVIDER_GOOGLE_CLIENT_ID || '';
const provider_google_client_secret = process.env.PROVIDER_GOOGLE_CLIENT_SECRET || '';
const provider_google_domain = process.env.PROVIDER_GOOGLE_DOMAIN || '';
const provider_google_scopes = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
];

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
app.get('/', (req, res) => {
    res.render('home', {
        app_title
    });
});
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
    res.render('login', {
        error: typeof req.query.error === 'string' && req.query.error !== '',
        error_text: req.query.error || '',
        info: typeof info_banner === 'string' && info_banner !== '',
        info_text: info_banner,
        host: req.query.host,
        redirect: req.query.url,
        banner_image: process.env.BANNER_IMAGE || `/images/bg-${random(1, 10)}.jpg`,
        app_title,
        app_header,
        logo,
        logo_url,
        email_placeholder,
        provider_google,
        sid: uuidv4()
    });
});
app.post('/login', async (req, res) => {
    const check = await authenticate(req.body.email, req.body.password, users);

    if(!check) {
        res.redirect(encodeURI(`/login?host=${req.body.host}&url=${req.body.redirect}&error=Invalid email/password!`));
        return;
    }

    res.redirect(`${req.body.host}/sso/redirect?redirect=${req.body.redirect}&jwt=${jwt.sign({email: req.body.email}, jwt_settings.secret, {
        algorithm: jwt_settings.algorithm,
        expiresIn: jwt_settings.expiresIn
    })}`);
});

/**
 * Configure OAuth Provider
 */
if(provider_google) {
    app.get('/provider/google', (req, res) => {
        // Create an OAuth2 client object from the credentials in our config file
        const oauth2Client = new GOAuth2(provider_google_client_id, provider_google_client_secret, `${req.protocol}://${req.get('host')}/provider/google/callback`);

        // Obtain the google login link to which we'll send our users to give us access
        const loginLink = oauth2Client.generateAuthUrl({
            access_type: 'offline', // Indicates that we need to be able to access data continously without the user constantly giving us consent
            scope: provider_google_scopes, // Using the access scopes from our config file
            state: btoa(JSON.stringify({
                host: req.query.host,
                redirect: req.query.redirect
            }))
        });

        return res.redirect(loginLink);
    });

    app.get('/provider/google/callback', (req, res) => {
        // Decode state
        const state = JSON.parse(atob(req.query.state));

        // Create an OAuth2 client object from the credentials in our config file
        const oauth2Client = new GOAuth2(provider_google_client_id, provider_google_client_secret, `${req.protocol}://${req.get('host')}/provider/google/callback`);

        if (req.query.error) {
            res.redirect(encodeURI(`/login?host=${state.host}&url=${state.redirect}&error=An error occurred during the connection to Google!`));
        } else {
            oauth2Client.getToken(req.query.code, (err, token) => {
                if (err) return res.redirect(encodeURI(`/login?host=${state.host}&url=${state.redirect}&error=An error occurred during the verification with Google!`));

                oauth2Client.credentials = token;
                const service = google.oauth2('v2');

                service.userinfo.get({
                    auth: oauth2Client
                }).then(response => {
                    if(typeof provider_google_domain === 'string' && provider_google_domain !== '') {
                        if(provider_google_domain !== response.data.hd) {
                            return res.redirect(encodeURI(`/login?host=${state.host}&url=${state.redirect}&error=This domain is not allowed!`));
                        }
                    }

                    res.redirect(`${state.host}/sso/redirect?redirect=${state.redirect}&jwt=${jwt.sign({email: response.data.email}, jwt_settings.secret, {
                        algorithm: jwt_settings.algorithm,
                        expiresIn: jwt_settings.expiresIn
                    })}`);
                });
            });
        }
    });
}

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
