'use strict';
const Account = require('./account');
const Admin = require('./admin');
const Async = require('async');
const Sodium = require('sodium').api;
const Joi = require('joi');
const MongoModels = require('mongo-models');

const AUTH_SALT = '0000000000000000';
const PRIVATE_KEY_SALT = '0000000000000001';
const ITERATIONS = 4;
const MEMORY = 65536;


class User extends MongoModels {

    /**
     * Generate an Argon2i hash for a given password.
     *
     * @param {str} password The user's password
     * @param callback
     */
    static generatePasswordHash(password, callback) {

        const passwordBuffer = Buffer.from(password, 'utf8');

        const encodedHash = Sodium.crypto_pwhash_argon2i_str(
            passwordBuffer,
            ITERATIONS,
            MEMORY
        );

        const hashParts = encodedHash.toString('utf8').split('$');
        const hash = hashParts[hashParts.length - 1].replace(/\0/g, '');
        const salt = hashParts[hashParts.length - 2];

        let authKey = User.generateArgonKey(32, new Buffer(hash, 'base64'), new Buffer(AUTH_SALT, 'utf8'));
        let privKeyEncKey = User.generateArgonKey(32, new Buffer(hash, 'base64'), new Buffer(PRIVATE_KEY_SALT, 'utf8'));

        callback(null, {
            password,
            privKeyEncKey: privKeyEncKey,
            authKey: authKey.toString('base64'),
            salt: salt
        });
    }

    /**
     * Key derivation based on Argon2i.
     *
     * @param {int} keyLength Length of derived key
     * @param {Buffer} pass Password for key derivation
     * @param {Buffer} salt Salt for key derivation
     * @returns {Buffer}
     */
    static generateArgonKey(keyLength, pass, salt) {
        let out = Buffer.allocUnsafe(keyLength);

        Sodium.crypto_pwhash_argon2i(
            out,
            pass,
            salt,
            ITERATIONS,
            MEMORY,
            Sodium.crypto_pwhash_argon2i_ALG_ARGON2I13
        );

        return out;
    }

    /**
     * Generate public and encrypted private key for a user.
     *
     * @param key   32 byte key to encrypt the private key. This should be the result
     *              of generateArgonKey with the password hash of the user.
     * @param callback
     */
    static generateKeypair(key, callback) {
        const keypair = Sodium.crypto_box_keypair();

        const encPrivateKey = User.encryptRecordUnderKey(
            keypair.secretKey,
            Buffer.from([], 'utf8'),
            Buffer.from(key, 'base64')
        );

        callback(null, {
            publicKey: keypair.publicKey.toString('base64'),
            encPrivateKey: encPrivateKey[0].toString('base64') + '$' + encPrivateKey[1].toString('base64')
        });
    }

    /**
     * Encrypt the file under the file key, return [nonce, encFile],
     * note that you have to hold on to the file metadata
     *
     * @param record - the record to be encrypted
     * @param metadata - the metadata for this record;
     *                 is required for decryption
     * @param key - the file key to encrypt this record
     * @return [nonce, ciphertext] where the decryption is
     *         decrypt(ciphertext, fileMetadata, nonce, fileKey)
     *         Both nonce and ciphertext are Buffers.
     */
    static encryptRecordUnderKey(record, metadata, key) {
        const nonce = User.randomBuffer(Sodium.crypto_aead_aes256gcm_NPUBBYTES);
        const cipherText = Sodium.crypto_aead_aes256gcm_encrypt(
            record,
            metadata,
            nonce,
            key);

        return [nonce, cipherText]
    }

    /**
     * Decrypt a cipher text given the metadata, nonce and key.
     *
     * @param {string} cipherText - Ciphertext to decrypt as base64 string
     * @param {string} metadata - Metadata associated with encryption
     * @param {string} nonce - Nonce used for encryption as base64 string
     * @param {string} key - Key to decrypt this record as base64 string
     * @return plainText
     */
    static decryptRecordUnderKey(cipherText, metadata, nonce, key) {
        const cipherTextBuffer = new Buffer(cipherText, 'base64');
        const metadataBuffer = new Buffer(metadata, 'utf8');
        const nonceBuffer = new Buffer(nonce, 'base64');
        const keyBuffer = new Buffer(key, 'base64');

        return Sodium.crypto_aead_aes256gcm_decrypt(
            cipherTextBuffer,
            metadataBuffer,
            nonceBuffer,
            keyBuffer);
    }

    /**
     * Creates and returns a random buffer of the specified length.
     * @param {int} length
     * @return {Buffer} random buffer of this length
     */
    static randomBuffer(length) {
        let buffer = Buffer.allocUnsafe(length);
        Sodium.randombytes_buf(buffer);
        return buffer;
    }

    static create(username, password, email, callback) {

        const self = this;

        Async.auto({
            passwordHash: function (done) {
                User.generatePasswordHash(password, done);
            },
            keypair: ['passwordHash', function (results, done) {
                User.generateKeypair(results.passwordHash.privKeyEncKey, done);
            }],
            newUser: ['keypair', function (results, done) {

                const document = {
                    isActive: true,
                    username: username.toLowerCase(),
                    password: results.passwordHash.authKey,
                    salt: results.passwordHash.salt,
                    publicKey: results.keypair.publicKey,
                    encPrivateKey: results.keypair.encPrivateKey,
                    email: email.toLowerCase(),
                    timeCreated: new Date()
                };

                self.insertOne(document, done);
            }]
        }, (err, results) => {

            if (err) {
                return callback(err);
            }

            results.newUser[0].password = results.passwordHash.password;

            callback(null, results.newUser[0]);
        });
    }

    static findByCredentials(username, password, callback) {

        const self = this;

        Async.auto({
            user: function (done) {

                const query = {
                    isActive: true
                };

                if (username.indexOf('@') > -1) {
                    query.email = username.toLowerCase();
                }
                else {
                    query.username = username.toLowerCase();
                }

                self.findOne(query, done);
            },
            passwordMatch: ['user', function (results, done) {

                if (!results.user) {
                    return done(null, false);
                }

                const pwKey = User.generateArgonKey(32, new Buffer(password, 'utf8'), new Buffer(results.user.salt, 'base64'));
                const authKey = User.generateArgonKey(32, pwKey, new Buffer(AUTH_SALT, 'utf8'));

                if (results.user.password === authKey.toString('base64')) {
                    done(null, {
                        pwKey: pwKey
                    });
                } else {
                    done(null, false);
                }
            }],
            privateKeyDecrypt: ['passwordMatch', function (results, done) {

                if (!results.passwordMatch) {
                    return callback();
                }

                const privateKeyEncKey = User.generateArgonKey(
                    32,
                    results.passwordMatch.pwKey,
                    new Buffer(PRIVATE_KEY_SALT, 'utf8')
                ).toString('base64');

                const encPrivateKey = results.user.encPrivateKey.split('$');

                const decryptedPrivateKey = User.decryptRecordUnderKey(
                    encPrivateKey[1],
                    '',
                    encPrivateKey[0],
                    privateKeyEncKey
                );

                done(null, decryptedPrivateKey);
            }]
        }, (err, results) => {

            if (err) {
                return callback(err);
            }

            if (results.passwordMatch) {
                results.user.decryptedPrivateKey = results.privateKeyDecrypt;
                return callback(null, results.user);
            }

            callback();
        });
    }

    static findByUsername(username, callback) {

        const query = {username: username.toLowerCase()};

        this.findOne(query, callback);
    }

    constructor(attrs) {

        super(attrs);

        Object.defineProperty(this, '_roles', {
            writable: true,
            enumerable: false
        });
    }

    canPlayRole(role) {

        if (!this.roles) {
            return false;
        }

        return this.roles.hasOwnProperty(role);
    }

    hydrateRoles(callback) {

        if (!this.roles) {
            this._roles = {};
            return callback(null, this._roles);
        }

        if (this._roles) {
            return callback(null, this._roles);
        }

        const self = this;
        const tasks = {};

        if (this.roles.account) {
            tasks.account = function (done) {

                Account.findById(self.roles.account.id, done);
            };
        }

        if (this.roles.admin) {
            tasks.admin = function (done) {

                Admin.findById(self.roles.admin.id, done);
            };
        }

        Async.auto(tasks, (err, results) => {

            if (err) {
                return callback(err);
            }

            self._roles = results;

            callback(null, self._roles);
        });
    }
}


User.collection = 'users';


User.schema = Joi.object().keys({
    _id: Joi.object(),
    isActive: Joi.boolean().default(true),
    username: Joi.string().token().lowercase().required(),
    password: Joi.string().required(),
    salt: Joi.string().required(),
    publicKey: Joi.string().required(),
    encPrivateKey: Joi.string().required(),
    email: Joi.string().email().lowercase().required(),
    roles: Joi.object().keys({
        admin: Joi.object().keys({
            id: Joi.string().required(),
            name: Joi.string().required()
        }),
        account: Joi.object().keys({
            id: Joi.string().required(),
            name: Joi.string().required()
        })
    }),
    resetPassword: Joi.object().keys({
        token: Joi.string().required(),
        expires: Joi.date().required()
    }),
    timeCreated: Joi.date()
});


User.indexes = [
    {key: {username: 1, unique: 1}},
    {key: {email: 1, unique: 1}}
];


module.exports = User;
