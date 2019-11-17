                            /**
                                 * Broadcast updates to client when the model changes
                            */

'use strict';

var logging = require('./logging.model');

exports.register = (socket)=>
{
  logging.schema.post('save', (doc)=>
  {
    onSave(socket, doc);
  });
  logging.schema.post('remove', (doc)=>
  {
    onRemove(socket, doc);
  });
}

function onSave(socket, doc)
{
  socket.emit('logging:save', doc);
}

function onRemove(socket, doc)
{
  socket.emit('logging:remove', doc);
}