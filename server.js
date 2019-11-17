const cors= require('cors');
const http = require('http');
const express = require('express');
const mongoose = require('mongoose');
const requestIp = require('request-ip');
const bodyParser = require('body-parser');
const config = require('./config/environment');
const database = require('./utils/connection');

let app = express();

app.use(cors());
app.use(config.assets);
app.use(requestIp.mw());
database.getConnection();
app.use(bodyParser.json({limit: '50mb'}));
app.use(bodyParser.urlencoded({ extended: true }));
require('./routes')(app);

// app.get('*', (req, res) => res.sendFile(config.view));

if(config.seedDB)
require('./config/seed');

let server = app.listen(config.port,() => console.log(`Server running on ${config.port} at ${config.env} environment`));