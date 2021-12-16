/**
 * Import vendor modules
 */
const fs = require('fs');
const md5 = require('apache-md5');
const crypt = require('apache-crypt');
const crypto = require('crypto');

/**
 * SHA1 encoding
 *
 * @param password
 * @returns {string}
 */
const sha1 = (password) => {
    const hash = crypto.createHash('sha1');
    hash.update(password);
    return hash.digest('base64');
};

/**
 * Check if the password matches the hash
 *
 * @param digest
 * @param password
 * @returns {Promise<unknown>}
 */
const checkPassword = (digest, password) => {
    return new Promise((resolve) => {
        if (digest.substr(0, 6) === '$apr1$') {
            resolve(digest === md5(password, digest));
        } else if (digest.substr(0, 4) === '$2y$') {
            console.warn('Bcrypt is not implemented!')
            resolve(false);
        } else if (digest.substr(0, 5) === '{SHA}') {
            resolve('{SHA}' + sha1(password) === digest);
        } else if (digest === password) {
            resolve(true);
        } else {
            resolve(crypt(password, digest) === digest);
        }
    });
}

/**
 * Check if a user/password matches the file
 *
 * @param username
 * @param password
 * @param htpasswd
 * @param json
 * @param useJson
 * @returns {Promise<unknown>}
 */
const authenticate = (username, password, htpasswd, json, useJson= false) => {
    return new Promise((resolve) => {
        if(!useJson) {
            const lines = htpasswd.split('\n');

            lines.forEach((line) => {
                const splitLine = line.split(':');
                if (splitLine[0] === username) {
                    resolve(checkPassword(splitLine[1], password));
                }
            });

            resolve(false);
        } else {
            const lines = JSON.parse(fs.readFileSync(json, 'utf-8'));

            lines.forEach((line) => {
                if (line.email === username) {
                    resolve(checkPassword(line.password, password));
                }
            });

            resolve(false);
        }
    });
};

/**
 * Hash a password that is htpasswd compatible
 *
 * @param password
 * @returns {string|*}
 */
const hash = (password) => {
    return md5(password);
}

/**
 * Export authenticate module
 */
module.exports = {authenticate, hash};
