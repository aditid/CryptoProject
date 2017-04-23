'use strict';
const Async = require('async');
const Bcrypt = require('bcrypt');
const Sodium = require('sodium').api;
const Joi = require('joi');
const MongoModels = require('mongo-models');
const Uuid = require('uuid');

// TODO remove bcrypt
class Session extends MongoModels {
    static generateKeyHash(callback) {

        const key = Uuid.v4();

        Async.auto({
            salt: function (done) {

                Bcrypt.genSalt(10, done);
            },
            hash: ['salt', function (results, done) {

                Bcrypt.hash(key, results.salt, done);
            }]
        }, (err, results) => {

            if (err) {
                return callback(err);
            }

            callback(null, {
                key,
                hash: results.hash
            });
        });
    }

    /**
     * Creates and returns a random buffer of the specified length.
     *
     * @param {int} length
     * @return {Buffer} random buffer of this length
     */
    static randomBuffer(length) {
        let buffer = Buffer.allocUnsafe(length);
        Sodium.randombytes_buf(buffer);
        return buffer;
    }

    /**
     * Split private key into two shares. Xor together to get private key again.
     *
     * @param {Buffer} privateKey Private key to secret share.
     * @param callback
     */
    static generatePrivateKeyShares(privateKey, callback) {
        const L = Sodium.crypto_box_SECRETKEYBYTES;

        const serverShare = Session.randomBuffer(L);
        let userShare = Buffer.allocUnsafe(L);

        for (let i = 0; i < L; i++) {
            userShare[i] = privateKey[i] ^ serverShare[i];
        }

        callback(null, {
            userShare: userShare,
            serverShare: serverShare
        });
    }

    static create(userId, privateKey, callback) {

        const self = this;

        Async.auto({
            keyHash: function (done) {
                Session.generateKeyHash(done);
            },
            keyShares: ['keyHash', function (results, done) {
                Session.generatePrivateKeyShares(privateKey, done);
            }],
            newSession: ['keyShares', function (results, done) {

                const document = {
                    userId,
                    key: results.keyHash.hash,
                    privateKeyShare: results.keyShares.serverShare.toString('base64'),
                    time: new Date()
                };

                self.insertOne(document, done);
            }],
            clean: ['newSession', function (results, done) {

                const query = {
                    userId,
                    key: {$ne: results.keyHash.hash}
                };

                self.deleteOne(query, done);
            }]
        }, (err, results) => {

            if (err) {
                return callback(err);
            }

            results.newSession[0].key = results.keyHash.key;
            results.newSession[0].privateKeyShare = results.keyShares.userShare.toString('base64');

            callback(null, results.newSession[0]);
        });
    }

    static findByCredentials(id, key, callback) {

        const self = this;

        Async.auto({
            session: function (done) {

                self.findById(id, done);
            },
            keyMatch: ['session', function (results, done) {

                if (!results.session) {
                    return done(null, false);
                }

                const source = results.session.key;
                Bcrypt.compare(key, source, done);
            }]
        }, (err, results) => {

            if (err) {
                return callback(err);
            }

            if (results.keyMatch) {
                return callback(null, results.session);
            }

            callback();
        });
    }
}


Session.collection = 'sessions';


Session.schema = Joi.object().keys({
    _id: Joi.object(),
    userId: Joi.string().required(),
    key: Joi.string().required(),
    privateKeyShare: Joi.string().required(),
    time: Joi.date().required()
});


Session.indexes = [
    {key: {userId: 1}}
];


module.exports = Session;
