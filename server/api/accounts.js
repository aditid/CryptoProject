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
    const Session = server.plugins['hapi-mongo-models'].Session;


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
                assign: 'privateKey',
                method : function (request, reply) {

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

                        reply(user);
                    });
                }
            }]
        },
        handler: function (request, reply) {

            Async.auto({
                encryption: function (done) {
                    console.log(request);
                }
            });

            const id = request.params.id;
            const update = {
                $push: {
                    notes: {
                        data: request.payload.data,
                        timeCreated: new Date(),
                        userCreated: {
                            id: request.auth.credentials.user._id.toString(),
                            name: request.auth.credentials.user.username
                        }
                    }
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

                reply({ message: 'Success.' });
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
