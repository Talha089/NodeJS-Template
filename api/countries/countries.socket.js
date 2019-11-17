/**
 * Broadcast updates to client when the model changes
 */

'use strict';

var countries = require('./countries.model');

exports.register = function(socket) {
  countries.schema.post('save', function (doc) {
    onSave(socket, doc);
  });
  countries.schema.post('remove', function (doc) {
    onRemove(socket, doc);
  });
}

function onSave(socket, doc, cb) {
  socket.emit('countries:save', doc);
}

function onRemove(socket, doc, cb) {
  socket.emit('countries:remove', doc);
}