const cors= require('cors');
const express = require('express');
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

if(config.seedDB)
require('./config/seed');
require('./routes')(app);

// app.get('*', (req, res) => res.sendFile(config.view));

app.listen(config.port,() => console.log(`Server running on ${config.port} in ${config.env} env`));