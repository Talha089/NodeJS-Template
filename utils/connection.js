const mongoose = require('mongoose');
const {mongo} = require('../config/environment');

function getConnection ()
{
    mongoose.connect(mongo.db_url, mongo.options);

    mongoose.connection.on('connected', () => console.log('Mongoose default connection open to ' + mongo.db_url));

    mongoose.connection.on('error', (err) => console.log('Mongoose default connection error: ' + err));

    mongoose.connection.on('disconnected', () => console.log('Mongoose default connection disconnected'));

    process.on('SIGINT', () => mongoose.connection.close(() => process.exit(0)));
}

module.exports = {getConnection}