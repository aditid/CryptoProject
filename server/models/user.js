'use strict';
const Account = require('./account');
const Admin = require('./admin');
const Async = require('async');
const Sodium = require('sodium').api;
const Joi = require('joi');
const MongoModels = require('mongo-models');

const AUTH_SALT = '0000000000000000';
const KEY_SALT = '0000000000000001';
const ITERATIONS = 4;
const MEMORY = 65536;


class User extends MongoModels {
    static generatePasswordHash(password, callback) {

        const passwordBuffer = Buffer.from(password, 'utf8');

        const encodedHash = Sodium.crypto_pwhash_argon2i_str(
            passwordBuffer,
            ITERATIONS,
            MEMORY
        );

        const hashParts = encodedHash.toString().split('$');
        const hash = hashParts[hashParts.length - 1];
        const salt = hashParts[hashParts.length - 2];

        let out = User.generateArgonKey(32, hash, AUTH_SALT);

        callback(null, {
            password,
            hash: out.toString('hex'),
            salt: salt
        });
    }

    /**
     * Key derivation based on Argon2i.
     *
     * @param key_length Length of derived key
     * @param pass Password for key derivation
     * @param salt Salt for key derivation
     * @returns {Buffer}
     */
    static generateArgonKey(key_length, pass, salt) {
        let out = Buffer.allocUnsafe(key_length);
        const password = Buffer.from(pass, 'utf8');
        salt = Buffer.from(salt, 'utf8');

        Sodium.crypto_pwhash_argon2i(
            out,
            password,
            salt,
            ITERATIONS,
            MEMORY,
            Sodium.crypto_pwhash_argon2i_ALG_ARGON2I13
        );

        return out;
    }

    static generateKeypair( password, callback ) {
        const keypair = Sodium.crypto_box_keypair();

        password = password + keyConcat;
        const passwordBuffer = Buffer.from(password, 'utf8');

        const hash = Sodium.crypto_pwhash_argon2i_str(
            passwordBuffer,
            Sodium.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,
            Sodium.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE
        );

        callback(null, {
            password,
            hash: hash.toString(),
            keypair: keypair
        });
    }

    static create(username, password, email, callback) {

        const self = this;

        Async.auto({
            passwordHash: this.generatePasswordHash.bind(this, password),
            //keypair: this.generateKeypair.bind(this, password),
            newUser: ['passwordHash', function (results, done) {

                const document = {
                    isActive: true,
                    username: username.toLowerCase(),
                    password: results.passwordHash.hash,
                    salt: results.passwordHash.salt,
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

                const source = Buffer.from(results.user.password, 'utf8');
                // User password is used both for authentication and key generation
                // Append "nonce" to generate two different hashes
                password = password + authConcat;

                let res = Sodium.crypto_pwhash_argon2i_str_verify(source, Buffer.from(password, 'utf8'));

                done(null, res);
            }]
        }, (err, results) => {

            if (err) {
                return callback(err);
            }

            if (results.passwordMatch) {
                return callback(null, results.user);
            }

            callback();
        });
    }

    static findByUsername(username, callback) {

        const query = { username: username.toLowerCase() };

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
    { key: { username: 1, unique: 1 } },
    { key: { email: 1, unique: 1 } }
];


module.exports = User;
