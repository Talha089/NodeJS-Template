'use strict';

const express = require('express');
const controller = require('./user.controller');
const auth = require('../../auth/auth.service');

const router = express.Router();

router.post('/', controller.create);
router.post('/auth', controller.authenticate);

router.get('/verifyEmail/:actCode', controller.verifyEmail); 
router.post('/resendVerification', controller.resendVerification);

router.get('/myProfile', auth.isAuthenticated(), controller.myProfile); 
router.put('/updateProfile', auth.isAuthenticated(), controller.updateProfile);

router.put('/setPassword', controller.setPassword); 
router.post('/forgotPassword', controller.forgotPassword);
router.get('/passwordKey/:tempPass', controller.passwordKey);
router.put('/changePassword', auth.isAuthenticated(), controller.changePassword);

module.exports = router;