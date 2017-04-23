'use strict';
const AuthPlugin = require('../auth');
const Boom = require('boom');
const Joi = require('joi');


const internals = {};


internals.applyRoutes = function (server, next) {

    const NoteEntry = server.plugins['hapi-mongo-models'].NoteEntry;


    server.route({
        method: 'GET',
        path: '/notes/{id}',
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

            NoteEntry.findById(request.params.id, (err, status) => {

                if (err) {
                    return reply(err);
                }

                if (!status) {
                    return reply(Boom.notFound('Document not found.'));
                }

                reply(status);
            });
        }
    });


    server.route({
        method: 'POST',
        path: '/notes',
        config: {
            auth: {
                strategy: 'simple',
                scope: 'admin'
            },
            validate: {
                payload: {
                    name: Joi.string().required(),
                    data: Joi.string().required()
                }
            },
            pre: [
                AuthPlugin.preware.ensureAdminGroup('root')
            ]
        },
        handler: function (request, reply) {

            const name = request.payload.name;
            const data = request.payload.data;

            NoteEntry.create(name, data, (err, note) => {

                if (err) {
                    return reply(err);
                }

                reply(note);
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
    name: 'notes'
};
