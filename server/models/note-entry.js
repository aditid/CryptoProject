'use strict';
const Joi = require('joi');
const MongoModels = require('mongo-models');


class NoteEntry extends MongoModels {}


NoteEntry.schema = Joi.object().keys({
    data: Joi.string().required(),
    timeCreated: Joi.date().required(),
    userCreated: Joi.object().keys({
        id: Joi.string().required(),
        name: Joi.string().lowercase().required()
    }).required(),
    _metadata: Joi.array().items({
        userId: Joi.string().required(),
        encryptedRecordKey: Joi.string().required()
    }).required()
});


module.exports = NoteEntry;
