/**
 * Import vendor modules
 */
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
 * @returns {Promise<unknown>}
 */
const authenticate = (username, password, htpasswd) => {
    return new Promise((resolve) => {
        const lines = htpasswd.split('\n');

        lines.forEach((line) => {
            const splitLine = line.split(':');
            if (splitLine[0] === username) {
                resolve(checkPassword(splitLine[1], password));
            }
        });

        resolve(false);
    });
};

/**
 * Export authenticate module
 *
 * @type {function(*=, *=, *): Promise<unknown>}
 */
module.exports = authenticate;
