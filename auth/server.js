/**
 * Import base packages
 */
const fs = require('fs');
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
const {authenticate, hash} = require('./modules/authenticate');

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
const json_path = dev ? `${__dirname}/db.json` : '/db/db.json';
const jwt_settings = {
    algorithm: 'HS512',
    secret: process.env.JWT_SECRET || 'ehKf5rmcLWkfeuTaTdbyZXZmVQQUAXdMWZ9R5fcJrCsgqGkdLUHXyTaARzeH',
    expiresIn: process.env.JWT_EXPIRATION || '24h'
};
const app_title = process.env.APP_TITLE || 'Auth Portal';
const logo = process.env.LOGO || '/images/logo_edit.png';
const logo_url = process.env.LOGO_URL || 'https://glenndehaan.com';
const info_banner = process.env.INFO_BANNER || '';
const email_placeholder = process.env.EMAIL_PLACEHOLDER || 'user@example.com';
const enable_direct_redirect = process.env.ENABLE_DIRECT_REDIRECT || false;
const auth_url = process.env.AUTH_URL || '';
const cookie_domain = process.env.COOKIE_DOMAIN || '';
const users = process.env.USERS || 'user@example.com:$apr1$jI2jqzEg$MyNJQxhcZFNygXP79xT/p.\n';
const users_json = process.env.USERS_JSON || false;
const users_json_admin = process.env.USERS_JSON_ADMIN || false;
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
 * Initialize DB
 */
if(users_json) {
    if(!fs.existsSync(json_path)) {
        log.info('Database Initialized!');

        fs.writeFileSync(json_path, JSON.stringify([
            {
                email: 'user@example.com',
                password: '$apr1$jI2jqzEg$MyNJQxhcZFNygXP79xT/p.',
                activation: null,
                created: 0
            }
        ]));
        fs.chmodSync(json_path, '666');
    }
}

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
    console.log('req.headers', req.headers);

    if(req.cookies && req.cookies.__auth_portal) {
        try {
            const check = jwt.verify(req.cookies.__auth_portal, jwt_settings.secret);
            if(check) {
                res.set('X-Auth-Portal-Error', '').set('X-Auth-Portal-User', check.email).status(200).send();
            } else {
                if(!enable_direct_redirect) {
                    res.set('X-Auth-Portal-Error', 'Invalid or expired login!').set('X-Auth-Portal-User', '').status(401).send();
                } else {
                    res.redirect(`${auth_url}?host=${req.headers['X-Forwarded-Proto']}://${req.headers['X-Forwarded-Host']}&url=${req.headers['X-Forwarded-Proto']}://${req.headers['X-Forwarded-Host']}${req.headers['X-Forwarded-Uri']}`)
                }
            }

            return;
        } catch (e) {
            if(!enable_direct_redirect) {
                res.set('X-Auth-Portal-Error', 'Invalid or expired login!').set('X-Auth-Portal-User', '').status(401).send();
            } else {
                res.redirect(`${auth_url}?host=${req.headers['X-Forwarded-Proto']}://${req.headers['X-Forwarded-Host']}&url=${req.headers['X-Forwarded-Proto']}://${req.headers['X-Forwarded-Host']}${req.headers['X-Forwarded-Uri']}`)
            }
            return;
        }
    }

    if(!enable_direct_redirect) {
        res.set('X-Auth-Portal-Error', '').set('X-Auth-Portal-User', '').status(401).send();
    } else {
        res.redirect(`${auth_url}?host=${req.headers['X-Forwarded-Proto']}://${req.headers['X-Forwarded-Host']}&url=${req.headers['X-Forwarded-Proto']}://${req.headers['X-Forwarded-Host']}${req.headers['X-Forwarded-Uri']}`)
    }
});
app.get('/login', (req, res) => {
    const hour = new Date().getHours();
    const timeHeader = hour < 12 ? 'Good Morning' : hour < 18 ? 'Good Afternoon' : 'Good Evening';

    res.render('login', {
        error: typeof req.query.error === 'string' && req.query.error !== '',
        error_text: req.query.error || '',
        info: typeof info_banner === 'string' && info_banner !== '',
        info_text: info_banner,
        host: req.query.host,
        redirect: req.query.url,
        banner_image: process.env.BANNER_IMAGE || `/images/bg-${random(1, 10)}.jpg`,
        app_title,
        app_header: process.env.APP_HEADER || timeHeader,
        logo,
        logo_url,
        email_placeholder,
        provider_google,
        sid: uuidv4()
    });
});
app.post('/login', async (req, res) => {
    const check = await authenticate(req.body.email, req.body.password, users, json_path, users_json);

    if(!check) {
        res.redirect(encodeURI(`/login?host=${req.body.host}&url=${req.body.redirect}&error=Invalid email/password!`));
        return;
    }

    res.cookie('__auth_portal', jwt.sign({email: req.body.email}, jwt_settings.secret, {
        algorithm: jwt_settings.algorithm,
        expiresIn: jwt_settings.expiresIn
    }), {httpOnly: true, secure: true, domain: cookie_domain}).redirect(req.body.redirect);
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

                    res.cookie('__auth_portal', jwt.sign({email: response.data.email}, jwt_settings.secret, {
                        algorithm: jwt_settings.algorithm,
                        expiresIn: jwt_settings.expiresIn
                    }), {httpOnly: true, secure: true, domain: cookie_domain}).redirect(state.redirect);
                });
            });
        }
    });
}

/**
 * Configure activate endpoint
 */
if(users_json) {
    app.get('/activate/:uuid', (req, res) => {
        const db = JSON.parse(fs.readFileSync(json_path, 'utf-8'));
        const find = db.filter((user) => {
            return user.activation === req.params.uuid;
        });

        if(find.length < 1) {
            res.status(404);
            res.send('Not Found!');

            return;
        }

        res.render('activate', {
            info: typeof info_banner === 'string' && info_banner !== '',
            info_text: info_banner,
            banner_image: process.env.BANNER_IMAGE || `/images/bg-${random(1, 10)}.jpg`,
            app_title,
            app_header: 'Activate Your Account',
            logo,
            logo_url,
            email: find[0].email,
            uuid: req.params.uuid,
            sid: uuidv4()
        });
    });

    app.post('/activate', (req, res) => {
        const db = JSON.parse(fs.readFileSync(json_path, 'utf-8'));
        const find = db.filter((user) => {
            return user.activation === req.body.uuid;
        });

        if(find.length < 1) {
            res.status(404);
            res.send('Not Found!');

            return;
        }

        const updatedDb = db.map((user) => {
            if(user.activation === req.body.uuid) {
                return {
                    ...user,
                    activation: null,
                    password: hash(req.body.password)
                }
            }

            return user;
        });

        fs.writeFileSync(json_path, JSON.stringify(updatedDb));

        res.render('activate_success', {
            info: typeof info_banner === 'string' && info_banner !== '',
            info_text: info_banner,
            banner_image: process.env.BANNER_IMAGE || `/images/bg-${random(1, 10)}.jpg`,
            app_title,
            app_header: 'Success',
            logo,
            logo_url,
            sid: uuidv4()
        });
    });

    if(users_json_admin) {
        app.get('/admin', (req, res) => {
            const db = JSON.parse(fs.readFileSync(json_path, 'utf-8'));

            res.render('admin', {
                info: typeof req.query.message === 'string' && req.query.message !== '',
                info_text: req.query.message || '',
                app_title,
                logo,
                logo_url,
                email_placeholder,
                db
            });
        });

        app.post('/admin/create', (req, res) => {
            const token = uuidv4();
            const db = JSON.parse(fs.readFileSync(json_path, 'utf-8'));

            db.push({
                email: req.body.email,
                password: '',
                activation: token,
                created: new Date().getTime()
            });

            fs.writeFileSync(json_path, JSON.stringify(db));

            res.redirect(encodeURI(`/admin?message=New user has been added: ${req.body.email}! URL: ${req.protocol}://${req.get('host')}/activate/${token}`));
        });

        app.get('/admin/reset', (req, res) => {
            const email = decodeURIComponent(req.query.email);
            const token = uuidv4();
            const db = JSON.parse(fs.readFileSync(json_path, 'utf-8'));

            const updatedDb = db.map((user) => {
                if (user.email === email) {
                    return {
                        ...user,
                        activation: token,
                        password: ''
                    }
                }

                return user;
            });

            fs.writeFileSync(json_path, JSON.stringify(updatedDb));

            res.redirect(encodeURI(`/admin?message=New activation link has been generated for: ${email}! URL: ${req.protocol}://${req.get('host')}/activate/${token}`));
        });

        app.get('/admin/delete', (req, res) => {
            const email = decodeURIComponent(req.query.email);
            const db = JSON.parse(fs.readFileSync(json_path, 'utf-8'));

            const updatedDb = db.filter((user) => {
                return user.email !== email;
            });

            fs.writeFileSync(json_path, JSON.stringify(updatedDb));

            res.redirect(encodeURI(`/admin?message=${email} has been removed!`));
        });
    }
}

/**
 * Setup default 404 message
 */
app.use((req, res) => {
    res.status(404);
    res.send('Not Found!');
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
