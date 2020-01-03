                        /**
                           * Main application routes
                        */

'use strict';

module.exports = (app) =>
{
  app.use('/auth', require('./auth'));

  app.use('/api/user', require('./api/user'));
  app.use('/api/logging', require('./api/logging'));
  app.use('/api/countries', require('./api/countries'));
};
