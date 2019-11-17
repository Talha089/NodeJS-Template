'use strict';

const express = require('express');
const controller = require('./user.controller');
const auth = require('../../auth/auth.service');

const router = express.Router();

router.post('/', controller.create);
router.post('/auth', controller.authenticate);
router.get('/verifyEmail/:actCode', controller.verifyEmail); 
router.post('/resendVerification', controller.resendVerification);

// router.post('/testMail', controller.testMail);

module.exports = router;
