'use strict';
                                        // ================================== //
                                        // Development specific configuration //
                                        // ================================== //
module.exports = {
  mongo:
  {
    db_url: 'mongodb+srv://malik:malik1234@cluster0-vm7xe.mongodb.net/tokenism-dev',
    options:
    {
      useNewUrlParser: true,
      useUnifiedTopology: true
  	},
    debug: false
  }
};
