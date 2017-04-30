'use strict';
const Async = require('async');
const AuthPlugin = require('../auth');
const Boom = require('boom');
const Joi = require('joi');
const Sodium = require('sodium').api;


const internals = {};


internals.applyRoutes = function (server, next) {

    const Account = server.plugins['hapi-mongo-models'].Account;
    const User = server.plugins['hapi-mongo-models'].User;
    const Status = server.plugins['hapi-mongo-models'].Status;


    server.route({
        method: 'GET',
        path: '/accounts',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            },
            validate: {
                query: {
                    fields: Joi.string(),
                    sort: Joi.string().default('_id'),
                    limit: Joi.number().default(20),
                    page: Joi.number().default(1)
                }
            }
        },
        handler: function (request, reply) {

            const query = {};
            const fields = request.query.fields;
            const sort = request.query.sort;
            const limit = request.query.limit;
            const page = request.query.page;

            Account.pagedFind(query, fields, sort, limit, page, (err, results) => {

                if (err) {
                    return reply(err);
                }

                reply(results);
            });
        }
    });


    server.route({
        method: 'GET',
        path: '/accounts/{id}',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            }
        },
        handler: function (request, reply) {

            Account.findById(request.params.id, (err, account) => {

                if (err) {
                    return reply(err);
                }

                if (!account) {
                    return reply(Boom.notFound('Document not found.'));
                }

                reply(account);
            });
        }
    });


    server.route({
        method: 'GET',
        path: '/accounts/my',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'account'
            }
        },
        handler: function (request, reply) {

            const id = request.auth.credentials.roles.account._id.toString();
            const fields = Account.fieldsAdapter('user name timeCreated');

            Account.findById(id, fields, (err, account) => {

                if (err) {
                    return reply(err);
                }

                if (!account) {
                    return reply(Boom.notFound('Document not found. That is strange.'));
                }

                reply(account);
            });
        }
    });


    server.route({
        method: 'POST',
        path: '/accounts',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            },
            validate: {
                payload: {
                    name: Joi.string().required()
                }
            }
        },
        handler: function (request, reply) {

            const name = request.payload.name;

            Account.create(name, (err, account) => {

                if (err) {
                    return reply(err);
                }

                reply(account);
            });
        }
    });


    server.route({
        method: 'PUT',
        path: '/accounts/{id}',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            },
            validate: {
                payload: {
                    name: Joi.object().keys({
                        first: Joi.string().required(),
                        middle: Joi.string().allow(''),
                        last: Joi.string().required()
                    }).required()
                }
            }
        },
        handler: function (request, reply) {

            const id = request.params.id;
            const update = {
                $set: {
                    name: request.payload.name
                }
            };

            Account.findByIdAndUpdate(id, update, (err, account) => {

                if (err) {
                    return reply(err);
                }

                if (!account) {
                    return reply(Boom.notFound('Document not found.'));
                }

                reply(account);
            });
        }
    });


    server.route({
        method: 'PUT',
        path: '/accounts/my',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'account'
            },
            validate: {
                payload: {
                    name: Joi.object().keys({
                        first: Joi.string().required(),
                        middle: Joi.string().allow(''),
                        last: Joi.string().required()
                    }).required()
                }
            }
        },
        handler: function (request, reply) {

            const id = request.auth.credentials.roles.account._id.toString();
            const update = {
                $set: {
                    name: request.payload.name
                }
            };
            const findOptions = {
                fields: Account.fieldsAdapter('user name timeCreated')
            };

            Account.findByIdAndUpdate(id, update, findOptions, (err, account) => {

                if (err) {
                    return reply(err);
                }

                reply(account);
            });
        }
    });


    server.route({
        method: 'PUT',
        path: '/accounts/{id}/user',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            },
            validate: {
                payload: {
                    username: Joi.string().lowercase().required()
                }
            },
            pre: [{
                assign: 'account',
                method: function (request, reply) {

                    Account.findById(request.params.id, (err, account) => {

                        if (err) {
                            return reply(err);
                        }

                        if (!account) {
                            return reply(Boom.notFound('Document not found.'));
                        }

                        reply(account);
                    });
                }
            }, {
                assign: 'user',
                method: function (request, reply) {

                    User.findByUsername(request.payload.username, (err, user) => {

                        if (err) {
                            return reply(err);
                        }

                        if (!user) {
                            return reply(Boom.notFound('User document not found.'));
                        }

                        if (user.roles &&
                            user.roles.account &&
                            user.roles.account.id !== request.params.id) {

                            return reply(Boom.conflict('User is already linked to another account. Unlink first.'));
                        }

                        reply(user);
                    });
                }
            }, {
                assign: 'userCheck',
                method: function (request, reply) {

                    if (request.pre.account.user &&
                        request.pre.account.user.id !== request.pre.user._id.toString()) {

                        return reply(Boom.conflict('Account is already linked to another user. Unlink first.'));
                    }

                    reply(true);
                }
            }]
        },
        handler: function (request, reply) {

            Async.auto({
                account: function (done) {

                    const id = request.params.id;
                    const update = {
                        $set: {
                            user: {
                                id: request.pre.user._id.toString(),
                                name: request.pre.user.username
                            }
                        }
                    };

                    Account.findByIdAndUpdate(id, update, done);
                },
                user: function (done) {

                    const id = request.pre.user._id;
                    const update = {
                        $set: {
                            'roles.account': {
                                id: request.pre.account._id.toString(),
                                name: request.pre.account.name.first + ' ' + request.pre.account.name.last
                            }
                        }
                    };

                    User.findByIdAndUpdate(id, update, done);
                }
            }, (err, results) => {

                if (err) {
                    return reply(err);
                }

                reply(results.account);
            });
        }
    });


    server.route({
        method: 'DELETE',
        path: '/accounts/{id}/user',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            },
            pre: [{
                assign: 'account',
                method: function (request, reply) {

                    Account.findById(request.params.id, (err, account) => {

                        if (err) {
                            return reply(err);
                        }

                        if (!account) {
                            return reply(Boom.notFound('Document not found.'));
                        }

                        if (!account.user || !account.user.id) {
                            return reply(account).takeover();
                        }

                        reply(account);
                    });
                }
            }, {
                assign: 'user',
                method: function (request, reply) {

                    User.findById(request.pre.account.user.id, (err, user) => {

                        if (err) {
                            return reply(err);
                        }

                        if (!user) {
                            return reply(Boom.notFound('User document not found.'));
                        }

                        reply(user);
                    });
                }
            }]
        },
        handler: function (request, reply) {

            Async.auto({
                account: function (done) {

                    const id = request.params.id;
                    const update = {
                        $unset: {
                            user: undefined
                        }
                    };

                    Account.findByIdAndUpdate(id, update, done);
                },
                user: function (done) {

                    const id = request.pre.user._id.toString();
                    const update = {
                        $unset: {
                            'roles.account': undefined
                        }
                    };

                    User.findByIdAndUpdate(id, update, done);
                }
            }, (err, results) => {

                if (err) {
                    return reply(err);
                }

                reply(results.account);
            });
        }
    });

    server.route({
        method: 'GET',
        path: '/accounts/{id}/notes',
        config: {
            auth: {
                strategy: 'simple',
                scope: ['admin', 'account']
            },
            validate: {
                query: {
                    keyShare: Joi.string().required()
                }
            },
            pre: [{
                assign: 'privateKey',
                method: function (request, reply) {

                    // Get private key of user, based on server and user key shares
                    if (!request.auth.credentials.session.privateKeyShare) {
                        return reply(Boom.notFound('Private key share not found.'));
                    }

                    let privateKeyShareServer = new Buffer(request.auth.credentials.session.privateKeyShare, 'base64');
                    let privateKeyShareUser = new Buffer(decodeURIComponent(request.query.keyShare), 'base64');
                    const L = Sodium.crypto_box_SECRETKEYBYTES;

                    let privateKey = Buffer.allocUnsafe(L);

                    for (let i = 0; i < L; i++) {
                        privateKey[i] = privateKeyShareServer[i] ^ privateKeyShareUser[i];
                    }

                    reply(privateKey);
                }
            }, {
                assign: 'user',
                method: function (request, reply) {

                    User.findById(request.params.id, (err, user) => {

                        if (err) {
                            return reply(err);
                        }

                        if (!user) {
                            return reply(Boom.notFound('User document not found.'));
                        }

                        reply(user);
                    });
                }
            }, {
                assign: 'account',
                method: function (request, reply) {

                    Account.findById(request.pre.user.roles.account.id, (err, account) => {

                        if (err) {
                            return reply(err);
                        }

                        if (!account) {
                            return reply(Boom.notFound('Document not found.'));
                        }

                        if (!account.user || !account.user.id) {
                            return reply(account).takeover();
                        }

                        reply(account);
                    });
                }
            }, {
                assign: 'verifyUser',
                method: function (request, reply) {

                    let validUser = false;
                    let notes = [];

                    if (!request.pre.account.notes) {
                        return reply(Boom.notFound('No notes found.'))
                    }

                    request.pre.account.notes.forEach(function (val, i, obj) {
                        for (let metadata of obj[i]._metadata) {
                            if (metadata.userId === request.auth.credentials.session.userId) {
                                validUser = true;
                                // Get rid of keys for different users that we cannot decrypt
                                // We only care about the key that is encrypted with our own public key
                                obj[i]._metadata = metadata;
                                notes.push(obj[i]);
                            }
                        }
                    });

                    // Overwrite all notes with ones we care about
                    request.pre.account.notes = notes;

                    if (!validUser) {
                        return reply(Boom.forbidden('No notes for account found.'));
                    }

                    reply();
                }
            }, {
                assign: 'decryptKey',
                method: function (request, reply) {

                    if (!request.pre.account.notes) {
                        return reply(Boom.notFound('No notes found.'))
                    }

                    request.pre.account.notes.forEach(function (val, i, obj) {

                        const nonce = obj[i]._metadata.encryptedRecordKey.split('$')[0];
                        const encRecordKey = obj[i]._metadata.encryptedRecordKey.split('$')[1];

                        const decryptedRecordKey = User.decryptRecordKey(
                            encRecordKey,
                            nonce,
                            obj[i].userCreated.publicKey,
                            request.pre.privateKey
                        );

                        obj[i]._metadata.decryptedRecordKey = decryptedRecordKey.toString('base64');
                    });

                    reply();
                }
            }]
        },
        handler: function (request, reply) {

            request.pre.account.notes.forEach(function (val, i, obj) {

                const nonce = obj[i].data.split('$')[0];
                const cipherText = obj[i].data.split('$')[1];

                obj[i].data = User.decryptRecordUnderKey(
                    cipherText,
                    '',
                    nonce,
                    obj[i]._metadata.decryptedRecordKey
                ).toString('utf8');
            });

            reply(request.pre.account.notes);
        }
    });


    server.route({
        method: 'POST',
        path: '/accounts/{id}/notes',
        config: {
            auth: {
                strategy: 'simple',
                scope: ['admin', 'account']
            },
            validate: {
                payload: {
                    data: Joi.string().required(),
                    keyShare: Joi.string().required()
                }
            },
            pre: [{
                // TODO refactor this into separate method
                assign: 'privateKey',
                method: function (request, reply) {

                    // Get private key of user, based on server and user key shares
                    if (!request.auth.credentials.session.privateKeyShare) {
                        return reply(Boom.notFound('Private key share not found.'));
                    }

                    let privateKeyShareServer = new Buffer(request.auth.credentials.session.privateKeyShare, 'base64');
                    let privateKeyShareUser = new Buffer(request.payload.keyShare, 'base64');
                    const L = Sodium.crypto_box_SECRETKEYBYTES;

                    let privateKey = Buffer.allocUnsafe(L);

                    for (let i = 0; i < L; i++) {
                        privateKey[i] = privateKeyShareServer[i] ^ privateKeyShareUser[i];
                    }

                    reply(privateKey);
                }
            }, {
                assign: 'publicKeys',
                method: function (request, reply) {

                    // Get all public keys to encrypt file key under
                    let userId;

                    if (request.auth.credentials.roles.admin) {
                        if (request.params.id === request.auth.credentials.session.userId) {
                            return reply(Boom.badRequest('You cannot create a note for an admin.'));
                        } else {
                            // Writing note for account, get their public key
                            userId = request.params.id;
                        }
                    } else {
                        // Writing note with account role, get public key of admin
                        userId = '000000000000000000000000';
                    }

                    User.findById(userId, (err, user) => {

                        if (err) {
                            return reply(err);
                        }

                        if (!user) {
                            return reply(Boom.notFound('User document not found.'));
                        }
                        if (!user.publicKey) {
                            return reply(Boom.notFound('No public key for user found.'));
                        }

                        // POST is for user ID, but notes are attached to account ID
                        // Store account data of target user temporary so we can extract ID later
                        reply({
                            account: user,
                            keys: [{
                                userId: request.auth.credentials.user._id.toString(),
                                publicKey: request.auth.credentials.user.publicKey
                            }, {
                                userId: user._id.toString(),
                                publicKey: user.publicKey
                            }]
                        });
                    });
                }
            }, {
                assign: 'encrypt',
                method: function (request, reply) {

                    // Generate random symmetric encryption key
                    let encKey = User.randomBuffer(Sodium.crypto_aead_aes256gcm_KEYBYTES);

                    // Encrypt file
                    let record = new Buffer(request.payload.data, 'utf8');
                    let encryptedRecord = User.encryptRecordUnderKey(
                        record,
                        new Buffer('', 'utf8'),
                        encKey
                    );

                    request.pre.publicKeys.keys.forEach(function (val, i, obj) {
                        const recordKey = User.encryptRecordKey(encKey, new Buffer(obj[i].publicKey, 'base64'), request.pre.privateKey);
                        obj[i].encryptedRecordKey = recordKey[0].toString('base64') + '$' + recordKey[1].toString('base64');
                        // Remove before writing to database, this information is not needed
                        delete obj[i].publicKey;
                    });

                    reply(encryptedRecord);
                }
            }]
        },
        handler: function (request, reply) {

            // POST is for user ID, but notes are attached to account ID
            const id = request.pre.publicKeys.account.roles.account.id;
            const update = {
                $push: {
                    notes: {
                        data: request.pre.encrypt[0].toString('base64') + '$' + request.pre.encrypt[1].toString('base64'),
                        timeCreated: new Date(),
                        userCreated: {
                            id: request.auth.credentials.user._id.toString(),
                            name: request.auth.credentials.user.username,
                            publicKey: request.auth.credentials.user.publicKey
                        },
                        _metadata: request.pre.publicKeys.keys
                    }
                }
            };

            Account.findByIdAndUpdate(id, update, (err, account) => {

                if (err) {
                    return reply(err);
                }

                if (!account) {
                    return reply(Boom.notFound('User document not found.'))
                }

                reply(account.notes);
            });
        }
    });


    server.route({
        method: 'POST',
        path: '/accounts/{id}/status',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            },
            validate: {
                payload: {
                    status: Joi.string().required()
                }
            },
            pre: [{
                assign: 'status',
                method: function (request, reply) {

                    Status.findById(request.payload.status, (err, status) => {

                        if (err) {
                            return reply(err);
                        }

                        reply(status);
                    });
                }
            }]
        },
        handler: function (request, reply) {

            const id = request.params.id;
            const newStatus = {
                id: request.pre.status._id.toString(),
                name: request.pre.status.name,
                timeCreated: new Date(),
                userCreated: {
                    id: request.auth.credentials.user._id.toString(),
                    name: request.auth.credentials.user.username
                }
            };
            const update = {
                $set: {
                    'status.current': newStatus
                },
                $push: {
                    'status.log': newStatus
                }
            };

            Account.findByIdAndUpdate(id, update, (err, account) => {

                if (err) {
                    return reply(err);
                }

                reply(account);
            });
        }
    });


    server.route({
        method: 'DELETE',
        path: '/accounts/{id}',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            },
            pre: [
                AuthPlugin.preware.ensureAdminGroup('root')
            ]
        },
        handler: function (request, reply) {

            Account.findByIdAndDelete(request.params.id, (err, account) => {

                if (err) {
                    return reply(err);
                }

                if (!account) {
                    return reply(Boom.notFound('Document not found.'));
                }

                reply({message: 'Success.'});
            });
        }
    });


    next();
};


exports.register = function (server, options, next) {

    server.dependency(['auth', 'hapi-mongo-models'], internals.applyRoutes);

    next();
};


exports.register.attributes = {
    name: 'account'
};
