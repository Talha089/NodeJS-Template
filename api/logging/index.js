'use strict';

const express = require('express');
const auth = require('../../auth/auth.service');
const controller = require('./logging.controller');

const router = express.Router();

router.get('/loginHistory', auth.isAuthenticated(), controller.loginHistory);

module.exports = router;